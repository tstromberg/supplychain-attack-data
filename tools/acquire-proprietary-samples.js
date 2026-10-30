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
const provenance = require("./provenance-store.js");

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
// Digests that appear only under `indicators` are invisible to `hashes`, and 96 of
// them sit in this corpus. They name a file *inside* the distributed artifact rather
// than the artifact itself — a `file_sha256` indicator is written "<path> <digest>" —
// so they are collected separately and recorded as members, never as the archive.
function memberDigests(artifact) {
  const declared = new Set(digests(artifact).map(x => x.value));
  const out = [];
  for (const indicator of artifact.indicators || []) {
    const text = String(indicator?.value || "");
    if (!/^(?:file_)?sha256$/i.test(String(indicator?.kind || "")) && !/[0-9a-f]{64}/i.test(text)) continue;
    for (const match of text.matchAll(/\b([0-9a-fA-F]{64})\b/g)) {
      const value = match[1].toLowerCase();
      if (declared.has(value) || out.some(x => x.value === value)) continue;
      out.push({ algorithm: "sha256", value, member: text.replace(match[1], "").trim() || null });
    }
  }
  return out;
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
          digests: digests(artifact), members: memberDigests(artifact), urls: distributionURLs(artifact),
          window: { from: day(artifact.start_date || attack.start_date), to: day(artifact.end_date || attack.end_date) } });
      }
    }
  }
  return artifacts;
}

// A vendor URL that no longer serves the artifact may still have been crawled while
// it did. The Internet Archive is the last URL lane: ask CDX what it holds, prefer a
// capture inside the incident window, and replay with the id_ modifier, which returns
// the original response rather than a rewritten page.
function day(value) {
  if (!value) return null;
  const text = String(value);
  const match = text.match(/(\d{4})-(\d{2})-(\d{2})/);
  return match ? `${match[1]}${match[2]}${match[3]}` : null;
}

async function waybackCaptures(url, window, timeoutMs) {
  const query = new URLSearchParams({ url, output: "json", filter: "statuscode:200", collapse: "digest", limit: "60" });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let rows;
  try {
    const response = await fetch(`http://web.archive.org/cdx/search/cdx?${query}`, { signal: controller.signal });
    if (!response.ok) return [];
    const text = await response.text();
    rows = text.trim() ? JSON.parse(text).slice(1) : [];
  } catch (_) {
    return [];
  } finally {
    clearTimeout(timer);
  }
  const stamps = rows.map(row => row[1]);
  // A capture from inside the window is the one that can hold the tampered bytes;
  // anything outside it is a comparator at best, so it is tried only afterwards.
  const inside = window.from && window.to
    ? stamps.filter(t => t.slice(0, 8) >= window.from && t.slice(0, 8) <= window.to)
    : [];
  const outside = stamps.filter(t => !inside.includes(t));
  return { inside, outside: window.from ? outside : stamps };
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
// Every digest the files already on disk satisfy, not just their SHA-256. A record
// citing an MD5 or SHA-1 would otherwise never match a held sample, so each run
// re-fetched it, overwriting any curated filename with the provider's own.
function existingHashes(m, sampleRoot) {
  const known = new Set();
  for (const sample of m.samples || []) {
    if (sample.sha256) known.add(String(sample.sha256).toLowerCase());
    if (!sampleRoot || !sample.path) continue;
    const file = path.join(sampleRoot, sample.path);
    if (!fs.existsSync(file) || sample.storage) continue;
    let bytes;
    try { bytes = fs.readFileSync(file); } catch (_) { continue; }
    for (const algorithm of ["md5", "sha1"]) {
      known.add(crypto.createHash(algorithm).update(bytes).digest("hex"));
    }
  }
  return known;
}

// A metadata-backed evidence record fills the sample slot without holding any of
// the artifact's bytes; it says so itself. Counting one as an acquisition ends the
// search for the artifact forever, which is how the closed-source lane came to
// report full coverage while 117 of its 165 samples were placeholders. Only a
// sample that carries recovered bytes counts.
function isAcquired(sample) {
  return sample.phase === "during" && sample.source?.kind !== "metadata_backed_evidence_record";
}
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
  return run("curl", ["-fsSL", "--compressed", "--retry", "1", "--max-time", String(Math.ceil(timeoutMs / 1000)),
    "-A", "supplychain-attack-data/1", "-o", output, url], timeoutMs).then(result => ({ result, output }));
}
function writeDirectSidecar(file, url, originalURL, waybackTimestamp) {
  const stat = fs.statSync(file);
  const fetchRecord = { url, original_url: originalURL || url, at: new Date().toISOString(), method: "GET",
    source: waybackTimestamp ? "wayback" : "direct_url" };
  if (waybackTimestamp) {
    fetchRecord.wayback_timestamp = waybackTimestamp;
    fetchRecord.derivation = ["Replayed with the id_ modifier, which returns the archived response rather than a rewritten page.",
      "curl --compressed was used, so a response stored with Content-Encoding is recorded here decoded."];
  }
  provenance.recordFor(file, { schema_version: 1, fetch: fetchRecord,
    artifact: { filename: path.basename(file), sha256: digest(file), size_bytes: stat.size } });
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
  // A provider that stores a file unnamed hands back a digest for a filename. When the
  // indicator said which member this is, use that name: "environmentAuthChecker.js"
  // tells a reader what they are looking at and a 64-character digest does not.
  const memberName = typeof target.member === "string" ? path.basename(target.member.replace(/\\/g, "/")) : "";
  const looksUnnamed = /^[0-9a-f]{64}(?:\.sample)?$/i.test(path.basename(file));
  const original = memberName && looksUnnamed && /^[A-Za-z0-9._+-]+$/.test(memberName)
    ? memberName
    : path.basename(file);
  const destDir = path.join(a.attackDir, "samples", safe(a.artifactId), "during");
  fs.mkdirSync(destDir, { recursive: true });
  let dest = path.join(destDir, original);
  if (fs.existsSync(dest) && digest(dest) !== measured) dest = path.join(destDir, `${safe(a.artifactId)}-${measured.slice(0, 12)}${path.extname(original) || ".sample"}`);
  if (!fs.existsSync(dest)) fs.renameSync(file, dest);
  /*
   * The collector's record goes into the digest-keyed store rather than travelling beside
   * the file. A rename no longer has to reach it -- the digest is what it is filed under --
   * but the renaming is still worth recording, because the name the provider used is part
   * of how these bytes were obtained.
   */
  if (sidecar.artifact) {
    const previous = sidecar.artifact.filename;
    if (previous && previous !== path.basename(dest)) {
      sidecar.artifact.filename = path.basename(dest);
      sidecar.fetch ||= {};
      sidecar.fetch.derivation ||= [];
      sidecar.fetch.derivation.push(`Renamed from ${previous} on capture: the provider stored this file unnamed and the incident record names it. Bytes unchanged.`);
    }
    provenance.recordFor(dest, sidecar);
  }
  if (fs.existsSync(sidecarPath)) fs.rmSync(sidecarPath);
  // Identity is the artifact's own bytes, stored exactly as they were distributed.
  const artifactSize = fs.statSync(dest).size;
  const digestMatchesReport = DIGEST_KINDS.has(target.kind) && digestWith(dest, target.kind) === target.value;

  const m = loadManifest(a);
  // Two providers can return the same bytes under different names. The manifest
  // keeps one entry per digest, so drop the file the superseded entry pointed at;
  // otherwise it stays on disk unlisted and the verifier rejects it.
  for (const prior of m.samples) {
    if (prior.artifact_id !== a.artifactId || prior.phase !== "during" || prior.sha256 !== measured) continue;
    const priorPath = path.resolve(path.join(a.attackDir, "samples"), prior.path || "");
    if (priorPath === path.resolve(dest)) continue;
    // Only the bytes go: provenance is keyed on the digest these bytes still have, and
    // the sample that replaces them is the same file under a better name.
    if (fs.existsSync(priorPath)) { fs.chmodSync(priorPath, 0o644); fs.rmSync(priorPath); }
  }
  m.samples = m.samples.filter(x => !(x.artifact_id === a.artifactId && x.phase === "during" && x.sha256 === measured));
  // Clearing the unresolved record discards its accumulated attempt history, so
  // only do it once every reported digest is accounted for. A partial success
  // leaves the record standing to describe what is still missing.
  // Only recovering the artifact itself closes out its unresolved record. A member
  // is a file from inside it, so acquiring every member still leaves the question of
  // whether anyone holds the distribution unanswered — and for an artifact whose only
  // digests are member digests, that question can never be answered by this lane.
  const onDisk = new Set([...existingHashes(m, path.join(a.attackDir, "samples")), measured]);
  if (!target.member && a.digests.length && a.digests.every(x => onDisk.has(x.value))) {
    m.unresolved = m.unresolved.filter(x => x.artifact_id !== a.artifactId || x.phase !== "during");
  }
  const fetchInfo = sidecar.fetch || {};
  m.samples.push({ artifact_id: a.artifactId, phase: "during", classification: target.member ? "malicious" : "affected",
    coordinate: DIGEST_KINDS.has(target.kind) ? `${target.kind}:${target.value}` : target.value,
    filename: path.basename(dest), path: path.relative(path.join(a.attackDir, "samples"), dest), sha256: measured,
    size: artifactSize, source: { url: fetchInfo.url || fallbackURL || "unknown", retrieved_at: fetchInfo.at || new Date().toISOString(), kind: sourceKind(fetchInfo.url || fallbackURL || "") },
    // A member digest identifies a file the artifact contained, so the recovered
    // bytes are exact for that file and say nothing about the container.
    ...(target.member ? { notes: [typeof target.member === "string"
      ? `A file from inside the distributed artifact, named by a reported file_sha256 indicator as ${target.member}. It is not the distribution itself; the container remains unresolved unless a separate entry holds it.`
      : "A file from inside the distributed artifact, named by a reported digest indicator. It is not the distribution itself."] } : {}),
    verification: digestMatchesReport
      ? { status: target.member ? "payload_only" : "exact", basis: [`reported_${target.kind}`, "measured_sha256"] }
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
  const m = loadManifest(a); const known = existingHashes(m, path.join(a.attackDir, "samples"));
  // An artifact can declare several digests — platforms, versions, or a container
  // and the payload inside it — and each names different bytes. Stopping at the
  // first one acquired leaves the rest permanently unfetched, so only the digests
  // already on disk are skipped, not the whole artifact.
  const wanted = [...a.digests, ...a.members];
  if (wanted.length && wanted.every(x => known.has(x.value))) {
    return { status: "existing", artifact: a };
  }
  if (!wanted.length && a.hashes.some(x => known.has(x))) return { status: "existing", artifact: a };
  const prior = m.unresolved.find(x => x.artifact_id === a.artifactId && x.phase === "during");
  if (prior && !options.retry) return { status: "unresolved_existing", artifact: a };
  const attempts = [];
  const acquired = [];
  process.stderr.write(`[${index}/${total}] ${a.attackId}/${a.artifactId} (${a.digests.length} hashes, ${a.urls.length} URLs)\n`);
  for (const { algorithm, value } of options.urlsOnly ? [] : a.digests) {
    if (known.has(value)) continue;
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
      known.add(captured); acquired.push(captured);
      continue;
    }
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  for (const { value, member } of options.urlsOnly ? [] : a.members) {
    if (known.has(value)) continue;
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "proprietary-member-"));
    const argv = ["fetch", "-o", tmp];
    if (options.hopper) argv.push("--hopper", options.hopper);
    argv.push(await hashFlag(options.forager), value);
    const r = await run(options.forager, argv, options.timeout * 1000);
    const files = findFiles(tmp);
    const label = member ? `member ${member}` : "member";
    attempts.push(`Forager ${label} SHA-256 ${value}: ${r.code === 0 && files.length === 1 ? "completed" : (r.stderr.trim().split("\n").at(-1) || `exit ${r.code}`)}`);
    if (r.code === 0 && files.length === 1 && !looksLikeHTML(files[0]) && digestWith(files[0], "sha256") === value) {
      const captured = record(a, { kind: "sha256", value, member: member || true }, files[0]);
      known.add(captured); acquired.push(captured);
    }
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  for (const url of (options.hashesOnly || acquired.length) ? [] : a.urls) {
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

    // The host no longer serves it; the Archive may still replay what it served.
    const captures = await waybackCaptures(url, a.window, options.timeout * 1000);
    const candidates = [...(captures.inside || []).slice(0, 4), ...(captures.outside || []).slice(0, 2)];
    if (!candidates.length) attempts.push(`Wayback ${url}: no captures`);
    for (const stamp of candidates) {
      const inWindow = (captures.inside || []).includes(stamp);
      const replay = `https://web.archive.org/web/${stamp}id_/${url}`;
      const wbTmp = fs.mkdtempSync(path.join(os.tmpdir(), "proprietary-wayback-"));
      const wb = await directURL(replay, wbTmp, options.timeout * 1000);
      const wbFiles = wb.result.code === 0 ? findFiles(wbTmp) : [];
      if (wb.result.code !== 0 || wbFiles.length !== 1) {
        attempts.push(`Wayback ${stamp} ${url}: ${wb.result.stderr.trim().split("\n").at(-1) || `exit ${wb.result.code}`}`);
        fs.rmSync(wbTmp, { recursive: true, force: true });
        continue;
      }
      if (looksLikeHTML(wbFiles[0])) {
        attempts.push(`Wayback ${stamp} ${url}: response was HTML, not an artifact`);
        fs.rmSync(wbTmp, { recursive: true, force: true });
        continue;
      }
      const measured = digest(wbFiles[0]);
      // With a reported digest, a match is proof and a mismatch is disqualifying.
      // Without one, only a capture from inside the window can be the during state;
      // an outside capture is a comparator and is not recorded as the artifact.
      if (a.hashes.length && !a.hashes.includes(measured)) {
        attempts.push(`Wayback ${stamp} ${url}: SHA-256 ${measured} did not match reported hashes`);
        fs.rmSync(wbTmp, { recursive: true, force: true });
        continue;
      }
      if (!a.hashes.length && !inWindow) {
        attempts.push(`Wayback ${stamp} ${url}: capture is outside the incident window and no digest binds it`);
        fs.rmSync(wbTmp, { recursive: true, force: true });
        continue;
      }
      writeDirectSidecar(wbFiles[0], replay, url, stamp);
      const captured = record(a, { kind: "url", value: replay }, wbFiles[0], replay);
      fs.rmSync(wbTmp, { recursive: true, force: true });
      return { status: "downloaded", artifact: a, sha256: captured };
    }
  }
  // Some digests may have been acquired even though others were not; that is a
  // partial success, and the unresolved record must survive to describe the rest.
  if (acquired.length) {
    if (a.digests.some(x => !acquired.includes(x.value))) recordFailure(a, attempts);
    return { status: "downloaded", artifact: a, sha256: acquired[0] };
  }
  recordFailure(a, attempts); return { status: "failed", artifact: a };
}
async function mapLimit(items, n, fn) {
  const result = new Array(items.length); let next = 0;
  async function worker() { while (next < items.length) { const i = next++; result[i] = await fn(items[i], i); } }
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker)); return result;
}
function writeReport(options, inventory, results) {
  // Artifact counts alone hide the work: an artifact declaring several digests reads
  // as acquired from its first file, so a run that doubles the recovered bytes can
  // move this number not at all. Count recovered files as well.
  const counts = { artifacts: inventory.length, with_sha256: 0, with_any_digest: 0, with_urls: 0, acquired: 0, unresolved: 0, pending: 0, existing: 0, recovered_samples: 0, exact_samples: 0, evidence_records: 0 };
  const byAttack = {};
  for (const a of inventory) {
    if (a.hashes.length) counts.with_sha256 += 1;
    if (a.digests.length) counts.with_any_digest += 1;
    if (a.urls.length) counts.with_urls += 1;
    const m = loadManifest(a); const has = m.samples.some(x => x.artifact_id === a.artifactId && isAcquired(x));
    const unresolved = m.unresolved.some(x => x.artifact_id === a.artifactId && x.phase === "during");
    if (has) counts.acquired += 1; else if (unresolved) counts.unresolved += 1; else counts.pending += 1;
    for (const sample of m.samples) {
      if (sample.artifact_id !== a.artifactId || sample.phase !== "during") continue;
      if (isAcquired(sample)) {
        counts.recovered_samples += 1;
        if (sample.verification?.status === "exact") counts.exact_samples += 1;
      } else counts.evidence_records += 1;
    }
    byAttack[a.attackId] ||= { artifacts: 0, acquired: 0, unresolved: 0, pending: 0 }; byAttack[a.attackId].artifacts += 1;
    byAttack[a.attackId][has ? "acquired" : unresolved ? "unresolved" : "pending"] += 1;
  }
  const report = { schema_version: 1, generated_at: new Date().toISOString(), scope: "closed-source attacks",
    policy: { layout: "proprietary/<incident>/samples/<artifact>/during", provenance: "Every acquired file is recorded in samples/provenance/<sha256>.json.", safety: "Capture-only; recovered artifacts are never executed." },
    inventory: counts, by_attack: byAttack, last_run: Object.fromEntries([...new Set(results.map(x => x.status))].map(s => [s, results.filter(x => x.status === s).length])) };
  fs.writeFileSync(options.report, yaml.dump(report, { noRefs: true, lineWidth: 100, sortKeys: false })); return report;
}
async function main() {
  const options = args(process.argv.slice(2)); const inventory = loadInventory();
  let queue = inventory.filter(a => { const m = loadManifest(a); const known = existingHashes(m, path.join(a.attackDir, "samples")); // Done means every reported digest is on disk, not just one of them.
    const wanted = [...a.digests, ...a.members];
    const has = wanted.length ? wanted.every(x => known.has(x.value)) : m.samples.some(x => x.artifact_id === a.artifactId && isAcquired(x)); const u = m.unresolved.some(x => x.artifact_id === a.artifactId && x.phase === "during"); return !has && (options.retry || !u) && (!options.urlsOnly || a.urls.length > 0) && (!options.hashesOnly || a.hashes.length > 0 || a.members.length > 0); });
  if (options.limit) queue = queue.slice(0, options.limit);
  let results = [];
  if (options.fetch) { if (!fs.existsSync(options.forager)) throw new Error(`Forager binary not found: ${options.forager}`); results = await mapLimit(queue, options.concurrency, (a, i) => attempt(a, options, i + 1, queue.length)); }
  const report = writeReport(options, inventory, results);
  process.stdout.write(yaml.dump({ queued: queue.length, inventory: report.inventory, last_run: report.last_run }, { noRefs: true, lineWidth: 100, sortKeys: false }));
}
main().catch(e => { process.stderr.write(`${e.stack || e.message}\n`); process.exitCode = 1; });
