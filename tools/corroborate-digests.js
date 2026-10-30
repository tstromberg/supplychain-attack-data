/*
 * Ask the sample feeds what they know about every digest the records cite.
 *
 * The lookups themselves live in Forager (`forager identify`), which is where the
 * provider credentials, pacing, and per-feed algorithm rules already are. This
 * script's job is the part Forager has no reason to know about: walking the
 * incident records, skipping digests already satisfied by a file on disk, and
 * reporting the answer against the artifact that cited it.
 *
 * It never downloads. It answers two questions that have to be settled before an
 * artifact is recorded unavailable:
 *
 *   1. Does the digest correspond to a file anyone has ever seen? A digest no
 *      feed recognises is a reason to doubt the digest rather than the artifact —
 *      `3cx` and `num2words` both sat unrecovered for exactly that reason.
 *   2. What is its SHA-256? Hopper and most feeds are SHA-256 only, so a record
 *      citing an MD5 or SHA-1 cannot reach them until something resolves it.
 *
 * A result marked `candidate` rather than `exact` came from Triage's analysis
 * index by MD5 or SHA-1, which can match a report that merely mentions the
 * digest. Treat it as a lead and confirm by fetching the bytes and re-measuring.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");
const { spawn, execFileSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/corroborate-digests.js [options]\n\n` +
    `  --scope oss|proprietary|all   Records to read (default: proprietary)\n` +
    `  --out PATH                    Write results as JSON here\n` +
    `  --limit N                     Stop after N digests\n` +
    `  --forager PATH                Forager binary (default: ${DEFAULT_FORAGER})\n` +
    `  --only SUBSTRING              Restrict to incidents whose id matches\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = { scope: "proprietary", forager: DEFAULT_FORAGER, timeout: 120000 };
  for (let i = 2; i < argv.length; i += 1) {
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) usage(1);
      i += 1;
      return next;
    };
    const arg = argv[i];
    if (arg === "--scope") options.scope = value();
    else if (arg === "--out") options.out = path.resolve(value());
    else if (arg === "--limit") options.limit = Number(value());
    else if (arg === "--only") options.only = value();
    else if (arg === "--forager") options.forager = path.resolve(value());
    else if (arg === "--help") usage(0);
    else usage(1);
  }
  return options;
}

function walk(dir, name, found = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(file, name, found);
    else if (entry.name === name) found.push(file);
  }
  return found;
}

const DIGEST = /\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b/g;

// Digests already satisfied by a file on disk, in every algorithm, so a record
// citing an MD5 is not re-checked when its sample is already held.
function heldDigests(roots) {
  const held = new Set();
  for (const root of roots) {
    for (const manifestFile of walk(path.join(ROOT, root), "manifest.yaml")) {
      if (path.basename(path.dirname(manifestFile)) !== "samples") continue;
      const manifest = yaml.load(fs.readFileSync(manifestFile, "utf8")) || {};
      for (const sample of manifest.samples || []) {
        if (sample.sha256) held.add(String(sample.sha256).toLowerCase());
        const file = path.join(path.dirname(manifestFile), sample.path || "");
        if (sample.storage || !sample.path || !fs.existsSync(file)) continue;
        let bytes;
        try {
          bytes = fs.readFileSync(file);
        } catch (_) {
          continue;
        }
        for (const algorithm of ["md5", "sha1"]) {
          held.add(crypto.createHash(algorithm).update(bytes).digest("hex"));
        }
        // A sample stored compressed satisfies its digests through the bytes
        // inside the wrapper. Measuring only the wrapper reports digests the
        // corpus already holds as unresolved, which sends the feeds a question
        // that was answered on disk.
        if (!/\.(xz|gz|bz2|zst)$/.test(file)) continue;
        try {
          const inner = execFileSync("7z", ["x", "-so", file], { maxBuffer: 1 << 30, timeout: 300000 });
          for (const algorithm of ["md5", "sha1", "sha256"]) {
            held.add(crypto.createHash(algorithm).update(inner).digest("hex"));
          }
        } catch (_) {
          // An unreadable wrapper leaves its digests wanted, which is correct.
        }
      }
    }
  }
  return held;
}

function collect(roots, only, held) {
  const targets = new Map();
  for (const root of roots) {
    for (const metaFile of walk(path.join(ROOT, root), "meta.yaml")) {
      let doc;
      try {
        doc = yaml.load(fs.readFileSync(metaFile, "utf8"));
      } catch (_) {
        continue;
      }
      for (const incident of Array.isArray(doc) ? doc : [doc]) {
        if (!incident || typeof incident !== "object") continue;
        const id = String(incident.id || path.basename(path.dirname(metaFile)));
        if (only && !id.includes(only)) continue;
        for (const artifact of incident.artifacts || []) {
          const where = `${id}/${artifact.id || artifact.name || "artifact"}`;
          const note = text => {
            for (const match of String(text || "").matchAll(DIGEST)) {
              const digest = match[1].toLowerCase();
              if (held.has(digest) || targets.has(digest)) continue;
              targets.set(digest, { where, metaFile });
            }
          };
          for (const hash of artifact.hashes || []) {
            note(typeof hash === "string" ? hash : Object.values(hash).join(" "));
          }
          for (const indicator of artifact.indicators || []) note(indicator && indicator.value);
        }
      }
    }
  }
  return targets;
}

const DEFAULT_FORAGER = "/private/tmp/forager-purl";

// One Forager invocation per digest. Forager asks only the feeds that index the
// digest's algorithm, marks a Triage MD5/SHA-1 hit as a candidate rather than as
// established, and holds the credentials, so nothing about the feeds is repeated
// here.
function identify(forager, digest, timeoutMs) {
  return new Promise(resolve => {
    const child = spawn(forager, ["identify", "--json", digest], { stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.stdout.on("data", chunk => { out += chunk; });
    child.on("error", () => { clearTimeout(timer); resolve([]); });
    child.on("close", () => {
      clearTimeout(timer);
      const line = out.split("\n").find(x => x.trim().startsWith("{"));
      if (!line) return resolve([]);
      try {
        resolve(JSON.parse(line).known || []);
      } catch (_) {
        resolve([]);
      }
    });
  });
}

async function main() {
  const options = parseArgs(process.argv);
  const roots = options.scope === "all" ? ["oss/attacks", "proprietary"]
    : options.scope === "oss" ? ["oss/attacks"] : ["proprietary"];
  const held = heldDigests(roots);
  let targets = [...collect(roots, options.only, held)];
  if (options.limit) targets = targets.slice(0, options.limit);
  process.stderr.write(`${targets.length} digests to corroborate (${held.size} already satisfied on disk)\n`);

  const results = [];
  for (const [digest, meta] of targets) {
    const found = await identify(options.forager, digest, options.timeout);
    const hit = found.find(x => x.Exact) || found[0] || null;
    const row = { digest, where: meta.where, ...(hit || { Provider: null }) };
    results.push(row);
    if (hit) {
      const bridged = hit.SHA256 && hit.SHA256.toLowerCase() !== digest ? ` sha256=${hit.SHA256.toLowerCase()}` : "";
      const confidence = hit.Exact ? "exact    " : "candidate";
      // Spectra answers with a coordinate rather than a filename.
      const subject = hit.Filename || hit.Coordinate || "";
      const verdict = hit.Malicious ? " (assessed malicious)" : "";
      process.stdout.write(`KNOWN   ${confidence} ${digest} ${meta.where} :: ${subject}${verdict} [${hit.Provider}]${bridged}\n`);
    } else {
      process.stdout.write(`UNKNOWN           ${digest} ${meta.where}\n`);
    }
  }
  const known = results.filter(x => x.Provider).length;
  process.stderr.write(`known ${known}  unknown ${results.length - known}\n`);
  if (options.out) fs.writeFileSync(options.out, `${JSON.stringify(results, null, 1)}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
