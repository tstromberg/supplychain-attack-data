#!/usr/bin/env node

/*
 * Match a record's unresolved digests against the contents of the archives it
 * already holds.
 *
 * A digest no feed recognises usually means one of two things, and they call for
 * opposite responses: the digest is wrong, or it names a file that was never
 * published on its own because it travelled inside something else. An installer,
 * a package archive, or a disk image is one artifact to a registry and many files
 * to a report, and reports routinely list the inner file's digest beside the
 * container's without saying which is which. When that happens the bytes are
 * already in the corpus and only the record is missing.
 *
 * So before an unresolved digest is treated as an unavailable artifact, the
 * cheapest question is whether the corpus is already holding it. This unpacks
 * each held sample into a temporary directory, measures every member, and reports
 * the digests that match. Nothing is executed: extraction is not installation,
 * and the unpacked copies are deleted as soon as they are measured.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const yaml = require("js-yaml");
const { execFileSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/resolve-member-digests.js [options]\n\n` +
    `  --scope oss|proprietary|all   Records to read (default: all)\n` +
    `  --only SUBSTRING              Restrict to incidents whose id matches\n` +
    `  --max-mb N                    Skip samples larger than this (default: 400)\n` +
    `  --out PATH                    Write matches as JSON here\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = { scope: "all", maxMB: 400 };
  for (let i = 2; i < argv.length; i += 1) {
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) usage(1);
      i += 1;
      return next;
    };
    const arg = argv[i];
    if (arg === "--scope") options.scope = value();
    else if (arg === "--only") options.only = value();
    else if (arg === "--max-mb") options.maxMB = Number(value());
    else if (arg === "--out") options.out = path.resolve(value());
    else if (arg === "--help") usage(0);
    else usage(1);
  }
  return options;
}

function walk(dir, name, found = []) {
  if (!fs.existsSync(dir)) return found;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(file, name, found);
    else if (entry.name === name) found.push(file);
  }
  return found;
}

const DIGEST = /^([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})$/;

// Every digest an artifact cites, in whatever form the record uses: a bare
// "sha256:..." string, the annotated mapping form, or an indicator carrying a
// file digest.
function citedDigests(artifact) {
  const out = new Set();
  const add = value => {
    const text = String(value || "").toLowerCase().replace(/^(md5|sha1|sha256):/, "").trim();
    if (DIGEST.test(text)) out.add(text);
  };
  for (const hash of artifact.hashes || []) {
    if (typeof hash === "string") add(hash);
    else for (const key of ["md5", "sha1", "sha256"]) add(hash[key]);
  }
  for (const indicator of artifact.indicators || []) {
    if (indicator && /sha256|sha1|md5/i.test(String(indicator.type || ""))) add(indicator.value);
  }
  return out;
}

function measureTree(dir, found = new Map()) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) measureTree(file, found);
    else if (entry.isFile()) {
      let bytes;
      try {
        bytes = fs.readFileSync(file);
      } catch (_) {
        continue;
      }
      for (const algorithm of ["md5", "sha1", "sha256"]) {
        const digest = crypto.createHash(algorithm).update(bytes).digest("hex");
        if (!found.has(digest)) found.set(digest, file);
      }
    }
  }
  return found;
}

function main() {
  const options = parseArgs(process.argv);
  const roots = options.scope === "oss" ? ["oss/attacks"]
    : options.scope === "proprietary" ? ["proprietary"] : ["oss/attacks", "proprietary"];

  const matches = [];
  for (const root of roots) {
    for (const metaFile of walk(path.join(ROOT, root), "meta.yaml")) {
      const dir = path.dirname(metaFile);
      let doc;
      try {
        doc = yaml.load(fs.readFileSync(metaFile, "utf8"));
      } catch (_) {
        continue;
      }
      for (const incident of Array.isArray(doc) ? doc : [doc]) {
        if (!incident || typeof incident !== "object") continue;
        const id = String(incident.id || path.basename(dir));
        if (options.only && !id.includes(options.only)) continue;

        // Digests the record cites, less the ones a held file already satisfies.
        const wanted = new Map();
        for (const artifact of incident.artifacts || []) {
          for (const digest of citedDigests(artifact)) wanted.set(digest, artifact.id || id);
        }
        if (!wanted.size) continue;
        const held = [];
        const sampleRoot = path.join(dir, "samples");
        const stack = fs.existsSync(sampleRoot) ? [sampleRoot] : [];
        while (stack.length) {
          const current = stack.pop();
          for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const file = path.join(current, entry.name);
            // The provenance store holds records, not payloads.
            if (entry.isDirectory()) { if (entry.name !== "provenance") stack.push(file); }
            else if (entry.isFile() && !file.endsWith(".forage.json") && !file.endsWith("manifest.yaml")) held.push(file);
          }
        }
        // A sample stored compressed satisfies its digest through the bytes
        // inside the wrapper, not the wrapper's own. Decompressing one is not
        // unpacking a container, and the single file it yields is the sample
        // itself, so its digest is held rather than a member of anything.
        for (const file of held) {
          const bytes = fs.readFileSync(file);
          for (const algorithm of ["md5", "sha1", "sha256"]) {
            wanted.delete(crypto.createHash(algorithm).update(bytes).digest("hex"));
          }
          if (!/\.(xz|gz|bz2|zst)$/.test(file)) continue;
          try {
            const inner = execFileSync("7z", ["x", "-so", file], { maxBuffer: 1 << 30, timeout: 300000 });
            for (const algorithm of ["md5", "sha1", "sha256"]) {
              wanted.delete(crypto.createHash(algorithm).update(inner).digest("hex"));
            }
          } catch (_) {
            // An unreadable wrapper leaves its digests wanted, which is correct.
          }
        }
        if (!wanted.size) continue;

        for (const file of held) {
          if (fs.statSync(file).size > options.maxMB * 1024 * 1024) continue;
          const temp = fs.mkdtempSync(path.join(os.tmpdir(), "members-"));
          try {
            try {
              execFileSync("7z", ["x", "-y", "-bso0", "-bse0", `-o${temp}`, file], { timeout: 300000 });
            } catch (_) {
              continue;
            }
            for (const [digest, where] of measureTree(temp)) {
              if (!wanted.has(digest)) continue;
              const member = path.relative(temp, where);
              matches.push({
                incident: id,
                artifact: wanted.get(digest),
                digest,
                container: path.relative(ROOT, file),
                member,
              });
              process.stdout.write(`MATCH ${digest} ${id}/${wanted.get(digest)}\n` +
                `      ${member}  inside  ${path.relative(ROOT, file)}\n`);
              wanted.delete(digest);
            }
          } finally {
            fs.rmSync(temp, { recursive: true, force: true });
          }
          if (!wanted.size) break;
        }
      }
    }
  }
  process.stdout.write(`\n${matches.length} unresolved digests are members of archives already held\n`);
  if (options.out) fs.writeFileSync(options.out, `${JSON.stringify(matches, null, 1)}\n`);
}

main();
