#!/usr/bin/env node

/*
 * Attempt retrieval of closed-source incident artifacts.  This is deliberately
 * a capture-only workflow: Forager downloads bytes and provenance sidecars;
 * this tool never opens, imports, installs, or executes a recovered artifact.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const yaml = require("js-yaml");
const { compressLargeSample } = require("./sample-storage.js");

const ROOT = path.resolve(__dirname, "..");
const PROPRIETARY = path.join(ROOT, "proprietary");
const DEFAULT_FORAGER = "/private/tmp/forager-purl";
const DEFAULT_REPORT = path.join(ROOT, "PROPRIETARY_SAMPLE_COVERAGE.yaml");

function usage(code = 0) {
  process.stderr.write(`Usage: node tools/acquire-proprietary-samples.js [options]\n\n` +
    `  --fetch                 Attempt retrieval (default: inventory only)\n` +
    `  --retry                 Retry existing unresolved records\n` +
    `  --urls-only             Skip hash providers and retry distribution URLs\n` +
    `  --hashes-only           Retry digest providers without URL downloads\n` +
    `  --hopper URL            Hopper base URL for SHA-256 lookups\n` +
    `  --forager PATH          Forager binary (default: ${DEFAULT_FORAGER})\n` +
    `  --concurrency N         Concurrent attempts (default: 8)\n` +
    `  --timeout N             Timeout per attempt in seconds (default: 15)\n` +
    `  --limit N               Maximum attempts; 0 means unlimited\n` +
    `  --report PATH           Coverage report path\n` +
    `  --help                  Show this help\n`);
  process.exit(code);
}

function args(argv) {
  const o = { fetch: false, retry: false, urlsOnly: false, hashesOnly: false, hopper: "", forager: DEFAULT_FORAGER,
    concurrency: 8, timeout: 15, limit: 0, report: DEFAULT_REPORT };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const value = () => { if (++i >= argv.length) usage(2); return argv[i]; };
    if (a === "--fetch") o.fetch = true;
    else if (a === "--retry") o.retry = true;
    else if (a === "--urls-only") o.urlsOnly = true;
    else if (a === "--hashes-only") o.hashesOnly = true;
    else if (a === "--hopper") o.hopper = value().replace(/\/$/, "");
    else if (a === "--forager") o.forager = path.resolve(value());
    else if (a === "--concurrency") o.concurrency = Number.parseInt(value(), 10);
    else if (a === "--timeout") o.timeout = Number.parseInt(value(), 10);
    else if (a === "--limit") o.limit = Number.parseInt(value(), 10);
    else if (a === "--report") o.report = path.resolve(value());
    else if (a === "--help" || a === "-h") usage(0);
    else usage(2);
  }
  if (!Number.isInteger(o.concurrency) || o.concurrency < 1 || o.concurrency > 32 ||
      !Number.isInteger(o.timeout) || o.timeout < 5 || o.timeout > 3600 ||
      !Number.isInteger(o.limit) || o.limit < 0) usage(2);
  return o;
}

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(file, out);
    else if (entry.name === "meta.yaml") out.push(file);
  }
  return out.sort();
}

function roots(value) { return Array.isArray(value) ? value : [value]; }
function safe(value) { return String(value).replace(/[^A-Za-z0-9._@+-]+/g, "-").replace(/^-+|-+$/g, "") || "artifact"; }
function sha256s(artifact) {
  return [...new Set((artifact.hashes || []).map(h => typeof h === "string" ? (h.toLowerCase().startsWith("sha256:") ? h.slice(7) : "") : h?.sha256)
    .filter(Boolean).map(String).map(x => x.trim().toLowerCase()).filter(x => /^[a-f0-9]{64}$/.test(x)))];
}
function md5s(artifact) {
  return [...new Set((artifact.hashes || []).map(h => typeof h === "string" ? (h.toLowerCase().startsWith("md5:") ? h.slice(4) : "") : h?.md5)
    .filter(Boolean).map(String).map(x => x.trim().toLowerCase()).filter(x => /^[a-f0-9]{32}$/.test(x)))];
}
function sha1s(artifact) {
  return [...new Set((artifact.hashes || []).map(h => typeof h === "string" ? (h.toLowerCase().startsWith("sha1:") ? h.slice(5) : "") : h?.sha1)
    .filter(Boolean).map(String).map(x => x.trim().toLowerCase()).filter(x => /^[a-f0-9]{40}$/.test(x)))];
}
// Closed-source incidents are often reported with only an MD5 or SHA-1, and the
// research providers index all three, so every published digest is a way in.
function digests(artifact) {
  return [
    ...sha256s(artifact).map(value => ({ algorithm: "sha256", value })),
    ...sha1s(artifact).map(value => ({ algorithm: "sha1", value })),
    ...md5s(artifact).map(value => ({ algorithm: "md5", value })),
  ];
}
function distributionURLs(artifact) {
  return [...new Set((artifact.locations || []).filter(x => x)
    .map(x => String(x.uri || "").trim()).filter(x => /^https?:\/\//i.test(x))
    // Home pages and package pseudo-URLs are context, not downloadable bytes.
    .filter(x => /\.(?:apk|appx|dmg|exe|iso|msi|pkg|rar|tar|tgz|war|zip|7z)(?:$|[?#])/i.test(x) ||
      /(?:download|release|archive|file|setup|installer)/i.test(x)) )];
}

function loadInventory() {
  const artifacts = [];
  for (const metaPath of walk(PROPRIETARY)) {
    const attackDir = path.dirname(metaPath);
    for (const attack of roots(yaml.load(fs.readFileSync(metaPath, "utf8")))) {
      if (!attack || typeof attack !== "object") continue;
      for (const artifact of attack.artifacts || []) {
        const id = String(artifact.id || artifact.package || artifact.name || "artifact");
        artifacts.push({ attackId: String(attack.id || path.basename(attackDir)), attackDir, metaPath,
          artifact, artifactId: id, hashes: sha256s(artifact), md5s: md5s(artifact),
          digests: digests(artifact), urls: distributionURLs(artifact) });
      }
    }
  }
  return artifacts;
}

function manifestFile(a) { return path.join(a.attackDir, "samples", "manifest.yaml"); }
function loadManifest(a) {
  const file = manifestFile(a);
  if (!fs.existsSync(file)) return { schema_version: 1, samples: [], unresolved: [] };
  const m = yaml.load(fs.readFileSync(file, "utf8")) || {};
  m.samples ||= []; m.unresolved ||= [];
  return m;
}
function saveManifest(a, m) {
  fs.mkdirSync(path.dirname(manifestFile(a)), { recursive: true });
  fs.writeFileSync(manifestFile(a), yaml.dump(m, { noRefs: true, lineWidth: 100, sortKeys: false }));
}
function existingHashes(m) { return new Set((m.samples || []).map(x => String(x.sha256 || "").toLowerCase()).filter(Boolean)); }
function findFiles(dir) {
  const out = [];
  const visit = d => { for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const f = path.join(d, e.name); if (e.isDirectory()) visit(f); else if (!e.name.endsWith(".forage.json")) out.push(f);
  }}; visit(dir); return out;
}
function digestWith(file, algorithm) { return crypto.createHash(algorithm).update(fs.readFileSync(file)).digest("hex"); }
function digest(file) { return digestWith(file, "sha256"); }

// Forager renamed its digest flag from -sha256 to -hash. The wrong spelling makes it
// print usage and exit non-zero, which is indistinguishable from "sample not found".
let hashFlagCache = "";
async function hashFlag(forager) {
  if (hashFlagCache) return hashFlagCache;
  const help = await run(forager, ["fetch", "--help"], 15000);
  hashFlagCache = /-{1,2}hash\b/.test(`${help.stdout}${help.stderr}`) ? "--hash" : "--sha256";
  return hashFlagCache;
}
function looksLikeHTML(file) {
  const head = fs.readFileSync(file).subarray(0, 4096).toString("utf8").toLowerCase();
  return /<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]/.test(head);
}
function run(command, argv, timeoutMs) {
  return new Promise(resolve => {
    const child = spawn(command, argv, { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "", timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGTERM"); }, timeoutMs);
    child.stdout.on("data", x => { stdout += x; }); child.stderr.on("data", x => { stderr += x; });
    child.on("error", e => resolve({ code: -1, stdout, stderr: `${stderr}${e.message}` }));
    child.on("close", code => { clearTimeout(timer); resolve({ code: timedOut ? 124 : code, stdout, stderr }); });
  });
}
function directURL(url, dir, timeoutMs) {
  let filename = "download.sample";
  try { filename = path.basename(new URL(url).pathname) || filename; } catch (_) {}
  filename = filename.replace(/[^A-Za-z0-9._+-]/g, "-");
  const output = path.join(dir, filename);
  return run("curl", ["-fsSL", "--retry", "1", "--max-time", String(Math.ceil(timeoutMs / 1000)),
    "-A", "supplychain-attack-data/1", "-o", output, url], timeoutMs).then(result => ({ result, output }));
}
function writeDirectSidecar(file, url) {
  const stat = fs.statSync(file);
  fs.writeFileSync(`${file}.forage.json`, JSON.stringify({ schema_version: 1,
    fetch: { url, original_url: url, at: new Date().toISOString(), method: "GET", source: "direct_url" },
    artifact: { filename: path.basename(file), sha256: digest(file), size_bytes: stat.size } }, null, 2) + "\n");
}
function sourceKind(url) {
  if (/web\.archive\.org\/web\//.test(url)) return "web_archive";
  if (/softwareheritage\.org/.test(url)) return "source_archive";
  if (/\/api\/file\//.test(url)) return "research_corpus";
  if (/bazaar\.abuse\.ch|tria\.ge/.test(url)) return "malware_repository";
  return "distribution";
}
const DIGEST_KINDS = new Set(["md5", "sha1", "sha256"]);

function record(a, target, file, fallbackURL) {
  const sidecarPath = `${file}.forage.json`;
  const sidecar = fs.existsSync(sidecarPath) ? JSON.parse(fs.readFileSync(sidecarPath, "utf8")) : {};
  const measured = digest(file);
  const original = path.basename(file);
  const destDir = path.join(a.attackDir, "samples", safe(a.artifactId), "during");
  fs.mkdirSync(destDir, { recursive: true });
  let dest = path.join(destDir, original);
  if (fs.existsSync(dest) && digest(dest) !== measured) dest = path.join(destDir, `${safe(a.artifactId)}-${measured.slice(0, 12)}${path.extname(original) || ".sample"}`);
  if (!fs.existsSync(dest)) fs.renameSync(file, dest);
  if (fs.existsSync(sidecarPath) && !fs.existsSync(`${dest}.forage.json`)) fs.renameSync(sidecarPath, `${dest}.forage.json`);
  // Identity is the artifact's own bytes; large ones are stored compressed.
  const artifactSize = fs.statSync(dest).size;
  const stored = compressLargeSample(dest);

  const m = loadManifest(a);
  m.samples = m.samples.filter(x => !(x.artifact_id === a.artifactId && x.phase === "during" && x.sha256 === measured));
  m.unresolved = m.unresolved.filter(x => x.artifact_id !== a.artifactId || x.phase !== "during");
  const fetchInfo = sidecar.fetch || {};
  m.samples.push({ artifact_id: a.artifactId, phase: "during", classification: "affected",
    coordinate: DIGEST_KINDS.has(target.kind) ? `${target.kind}:${target.value}` : target.value,
    filename: path.basename(dest), path: path.relative(path.join(a.attackDir, "samples"), stored.path), sha256: measured,
    size: artifactSize, ...(stored.storage ? { storage: stored.storage } : {}), source: { url: fetchInfo.url || fallbackURL || "unknown", retrieved_at: fetchInfo.at || new Date().toISOString(), kind: sourceKind(fetchInfo.url || fallbackURL || "") },
    verification: DIGEST_KINDS.has(target.kind) && digestWith(dest, target.kind) === target.value
      ? { status: "exact", basis: [`reported_${target.kind}`, "measured_sha256"] }
      : { status: "probable_exact", basis: ["distribution_source", "measured_sha256"] } });
  saveManifest(a, m);
  return measured;
}
function recordFailure(a, attempts) {
  const m = loadManifest(a);
  let u = m.unresolved.find(x => x.artifact_id === a.artifactId && x.phase === "during");
  if (!u) { u = { artifact_id: a.artifactId, phase: "during", status: "unavailable", hashes: a.digests.map(x => `${x.algorithm}: ${x.value}`), locations: a.urls, attempts: [] }; m.unresolved.push(u); }
  u.last_attempted_at = new Date().toISOString(); u.attempts ||= [];
  for (const x of attempts) if (!u.attempts.includes(x)) u.attempts.push(x);
  saveManifest(a, m);
}

async function attempt(a, options, index, total) {
  const m = loadManifest(a); const known = existingHashes(m);
  if (a.hashes.some(x => known.has(x))) return { status: "existing", artifact: a };
  const prior = m.unresolved.find(x => x.artifact_id === a.artifactId && x.phase === "during");
  if (prior && !options.retry) return { status: "unresolved_existing", artifact: a };
  const attempts = [];
  process.stderr.write(`[${index}/${total}] ${a.attackId}/${a.artifactId} (${a.digests.length} hashes, ${a.urls.length} URLs)\n`);
  for (const { algorithm, value } of options.urlsOnly ? [] : a.digests) {
    const label = algorithm.toUpperCase();
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "proprietary-acquire-"));
    const argv = ["fetch", "-o", tmp]; if (options.hopper) argv.push("--hopper", options.hopper); argv.push(await hashFlag(options.forager), value);
    const r = await run(options.forager, argv, options.timeout * 1000);
    const files = findFiles(tmp);
    attempts.push(`Forager ${label} ${value}: ${r.code === 0 && files.length === 1 ? "completed" : (r.stderr.trim().split("\n").at(-1) || `exit ${r.code}`)}`);
    if (r.code === 0 && files.length === 1 && !looksLikeHTML(files[0])) {
      const measured = digestWith(files[0], algorithm);
      if (measured !== value) {
        attempts.push(`Forager ${label} ${value}: downloaded ${label} ${measured} did not match requested digest`);
        fs.rmSync(tmp, { recursive: true, force: true });
        continue;
      }
      const captured = record(a, { kind: algorithm, value }, files[0]); fs.rmSync(tmp, { recursive: true, force: true });
      return { status: "downloaded", artifact: a, sha256: captured };
    }
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  for (const url of options.hashesOnly ? [] : a.urls) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "proprietary-acquire-"));
    const r = await run(options.forager, ["fetch", "-o", tmp, url], options.timeout * 1000);
    const files = findFiles(tmp);
    attempts.push(`Forager URL ${url}: ${r.code === 0 && files.length === 1 ? "completed" : (r.stderr.trim().split("\n").at(-1) || `exit ${r.code}`)}`);
    if (r.code === 0 && files.length === 1 && !looksLikeHTML(files[0])) {
      const measured = digest(files[0]);
      if (a.hashes.length && !a.hashes.includes(measured)) {
        attempts.push(`Forager URL ${url}: downloaded SHA-256 ${measured} did not match reported hashes`);
        fs.rmSync(tmp, { recursive: true, force: true });
        continue;
      }
      const captured = record(a, { kind: "url", value: url }, files[0], url); fs.rmSync(tmp, { recursive: true, force: true });
      return { status: "downloaded", artifact: a, sha256: captured };
    }
    fs.rmSync(tmp, { recursive: true, force: true });

    // Forager intentionally accepts only immutable package/archive URL forms.
    // Proprietary incident records often contain ordinary vendor URLs, so use
    // curl as a narrow capture fallback and retain equivalent provenance.
    const directTmp = fs.mkdtempSync(path.join(os.tmpdir(), "proprietary-url-"));
    const direct = await directURL(url, directTmp, options.timeout * 1000);
    const directFiles = direct.result.code === 0 ? findFiles(directTmp) : [];
    if (direct.result.code === 0 && directFiles.length === 1 && !looksLikeHTML(directFiles[0])) {
      const measured = digest(directFiles[0]);
      if (a.hashes.length && !a.hashes.includes(measured)) {
        attempts.push(`Direct URL ${url}: downloaded SHA-256 ${measured} did not match reported hashes`);
        fs.rmSync(directTmp, { recursive: true, force: true });
        continue;
      }
      writeDirectSidecar(directFiles[0], url);
      const captured = record(a, { kind: "url", value: url }, directFiles[0], url);
      fs.rmSync(directTmp, { recursive: true, force: true });
      return { status: "downloaded", artifact: a, sha256: captured };
    }
    if (direct.result.code === 0 && directFiles.length === 1 && looksLikeHTML(directFiles[0])) {
      attempts.push(`Direct URL ${url}: response was HTML, not an artifact`);
    }
    attempts.push(`Direct URL ${url}: ${direct.result.stderr.trim().split("\n").at(-1) || `exit ${direct.result.code}`}`);
    fs.rmSync(directTmp, { recursive: true, force: true });
  }
  recordFailure(a, attempts); return { status: "failed", artifact: a };
}
async function mapLimit(items, n, fn) {
  const result = new Array(items.length); let next = 0;
  async function worker() { while (next < items.length) { const i = next++; result[i] = await fn(items[i], i); } }
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker)); return result;
}
function writeReport(options, inventory, results) {
  const counts = { artifacts: inventory.length, with_sha256: 0, with_any_digest: 0, with_urls: 0, acquired: 0, unresolved: 0, pending: 0, existing: 0 };
  const byAttack = {};
  for (const a of inventory) {
    if (a.hashes.length) counts.with_sha256 += 1;
    if (a.digests.length) counts.with_any_digest += 1;
    if (a.urls.length) counts.with_urls += 1;
    const m = loadManifest(a); const has = m.samples.some(x => x.artifact_id === a.artifactId && x.phase === "during");
    const unresolved = m.unresolved.some(x => x.artifact_id === a.artifactId && x.phase === "during");
    if (has) counts.acquired += 1; else if (unresolved) counts.unresolved += 1; else counts.pending += 1;
    byAttack[a.attackId] ||= { artifacts: 0, acquired: 0, unresolved: 0, pending: 0 }; byAttack[a.attackId].artifacts += 1;
    byAttack[a.attackId][has ? "acquired" : unresolved ? "unresolved" : "pending"] += 1;
  }
  const report = { schema_version: 1, generated_at: new Date().toISOString(), scope: "closed-source attacks",
    policy: { layout: "proprietary/<incident>/samples/<artifact>/during", provenance: "Adjacent .forage.json sidecars are mandatory for acquired files.", safety: "Capture-only; recovered artifacts are never executed." },
    inventory: counts, by_attack: byAttack, last_run: Object.fromEntries([...new Set(results.map(x => x.status))].map(s => [s, results.filter(x => x.status === s).length])) };
  fs.writeFileSync(options.report, yaml.dump(report, { noRefs: true, lineWidth: 100, sortKeys: false })); return report;
}
async function main() {
  const options = args(process.argv.slice(2)); const inventory = loadInventory();
  let queue = inventory.filter(a => { const m = loadManifest(a); const has = m.samples.some(x => x.artifact_id === a.artifactId && x.phase === "during"); const u = m.unresolved.some(x => x.artifact_id === a.artifactId && x.phase === "during"); return !has && (options.retry || !u) && (!options.urlsOnly || a.urls.length > 0) && (!options.hashesOnly || a.hashes.length > 0); });
  if (options.limit) queue = queue.slice(0, options.limit);
  let results = [];
  if (options.fetch) { if (!fs.existsSync(options.forager)) throw new Error(`Forager binary not found: ${options.forager}`); results = await mapLimit(queue, options.concurrency, (a, i) => attempt(a, options, i + 1, queue.length)); }
  const report = writeReport(options, inventory, results);
  process.stdout.write(yaml.dump({ queued: queue.length, inventory: report.inventory, last_run: report.last_run }, { noRefs: true, lineWidth: 100, sortKeys: false }));
}
main().catch(e => { process.stderr.write(`${e.stack || e.message}\n`); process.exitCode = 1; });
