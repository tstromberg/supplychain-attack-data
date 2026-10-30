#!/usr/bin/env node

/*
 * Ingests removed npm releases from a local research corpus.
 *
 * Backstabber's Knife Collection keeps the published tarball of a malicious release
 * alongside the registry metadata that described it, laid out as
 * <package>/<version>/<name>-<version>.tgz plus meta.json.zst. That metadata is what
 * makes this the strongest lane in the corpus: it carries npm's own dist.integrity and
 * dist.shasum for the version, so a recovered archive is checked against the digest the
 * registry published rather than merely against the coordinate it claims. A mirror
 * capture is probable_exact; a capture the registry's own integrity binds is exact.
 *
 *   node tools/acquire-research-corpus.js --corpus /path/to/samples/npm
 *
 * The corpus itself lives on smaug under
 * /data/samples/bad/datasets/various/Backstabber's Knife Collection, and is also
 * reachable by digest through Hopper. Point --corpus at a local copy of its npm tree.
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");
const { execFileSync } = require("node:child_process");
const yaml = require("js-yaml");
const { compressLargeSample } = require("./sample-storage.js");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];
const CORPUS_NAME = "Backstabber's Knife Collection";

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/acquire-research-corpus.js --corpus DIR [options]\n\n` +
    `  --corpus DIR    Local copy of the corpus's npm tree\n` +
    `  --only SUB      Restrict to incidents whose id or directory matches\n` +
    `  --limit N       Maximum releases ingested; 0 means unlimited\n` +
    `  --dry-run       Report what would be ingested and stop\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = { limit: 0 };
  for (let i = 2; i < argv.length; i += 1) {
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) usage(1);
      i += 1;
      return next;
    };
    const arg = argv[i];
    if (arg === "--corpus") options.corpus = path.resolve(value());
    else if (arg === "--only") options.only = value().toLowerCase();
    else if (arg === "--limit") options.limit = Number(value());
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--help" || arg === "-h") usage(0);
    else usage(1);
  }
  if (!options.corpus) usage(1);
  return options;
}

function stringValues(value) {
  if (!Array.isArray(value)) return [];
  return value.map(x => String(x).trim()).filter(Boolean);
}

function encodeName(name) {
  return String(name).split("/").map(encodeURIComponent).join("/");
}

function safeSegment(value) {
  const result = String(value).replace(/[^A-Za-z0-9._@+-]+/g, "-").replace(/^-+|-+$/g, "");
  return result || "artifact";
}

function walkMetaFiles(dir, found = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walkMetaFiles(file, found);
    else if (entry.name === "meta.yaml") found.push(file);
  }
  return found;
}

/*
 * targets collects every npm release the records name that still has no during sample.
 * Coverage is read from the manifest rather than from disk, because a sample recorded
 * for the artifact under any filename already answers for it.
 */
function targets(options) {
  const found = [];
  for (const scope of SCOPES) {
    for (const metaPath of walkMetaFiles(scope)) {
      const attackDir = path.dirname(metaPath);
      const manifestFile = path.join(attackDir, "samples", "manifest.yaml");
      const manifest = fs.existsSync(manifestFile)
        ? yaml.load(fs.readFileSync(manifestFile, "utf8")) || {}
        : {};
      const covered = new Set((manifest.samples || [])
        .filter(s => s.phase === "during").map(s => s.artifact_id));
      for (const record of yaml.load(fs.readFileSync(metaPath, "utf8")) || []) {
        if (!record || typeof record !== "object") continue;
        const incident = String(record.id || path.basename(attackDir));
        if (options.only && !`${incident} ${attackDir}`.toLowerCase().includes(options.only)) continue;
        for (const artifact of record.artifacts || []) {
          if (String(artifact.ecosystem || "").toLowerCase() !== "npm") continue;
          if (covered.has(artifact.id)) continue;
          const name = String(artifact.package || artifact.name || "").trim();
          if (!name) continue;
          for (const version of stringValues(artifact.versions)) {
            found.push({ incident, attackDir, manifestFile, artifactId: String(artifact.id), name, version });
          }
        }
      }
    }
  }
  return found;
}

// The registry metadata the corpus stored beside the archive, or null when absent.
function registryMetadata(dir) {
  const file = path.join(dir, "meta.json.zst");
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(execFileSync("zstd", ["-dc", file], { maxBuffer: 64 * 1024 * 1024 }).toString());
  } catch (_) {
    return null;
  }
}

// The archive's own package.json, so bytes are never trusted on their path alone.
function declaredCoordinate(body) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "corpus-"));
  try {
    fs.writeFileSync(path.join(scratch, "archive.tar"), zlib.gunzipSync(body));
    execFileSync("tar", ["-xf", "archive.tar", "-C", scratch, "package/package.json"], { cwd: scratch, stdio: "ignore" });
    const manifest = JSON.parse(fs.readFileSync(path.join(scratch, "package", "package.json"), "utf8"));
    return { name: manifest.name, version: String(manifest.version) };
  } catch (_) {
    return null;
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

/*
 * verify checks the archive against what npm published for that version. dist.integrity
 * is a base64 SHA-512 over the tarball and dist.shasum its SHA-1; either binding the
 * bytes makes this the release npm served, not merely an archive that claims to be.
 */
function verify(body, dist) {
  const basis = [];
  if (dist?.integrity) {
    const [algorithm, expected] = String(dist.integrity).split("-", 2);
    if (algorithm && expected) {
      const actual = crypto.createHash(algorithm.replace("sha", "sha")).update(body).digest("base64");
      if (actual !== expected) return { status: "mismatch", basis: [`registry_${algorithm}_integrity_mismatch`] };
      basis.push(`registry_${algorithm}_integrity`);
    }
  }
  if (dist?.shasum) {
    const actual = crypto.createHash("sha1").update(body).digest("hex");
    if (actual !== String(dist.shasum)) return { status: "mismatch", basis: ["registry_shasum_mismatch"] };
    basis.push("registry_shasum");
  }
  if (basis.length === 0) return { status: "probable_exact", basis: ["research_corpus_retained_archive"] };
  return { status: "exact", basis };
}

function main() {
  const options = parseArgs(process.argv);
  const queue = targets(options);
  const list = options.limit > 0 ? queue.slice(0, options.limit) : queue;
  process.stderr.write(`${queue.length} npm releases without a during sample, checking ${list.length}\n`);

  const manifests = new Map();
  let ingested = 0;
  let absent = 0;
  let rejected = 0;

  for (const target of list) {
    const dir = path.join(options.corpus, target.name, target.version);
    const archive = fs.existsSync(dir)
      ? fs.readdirSync(dir).find(f => f.endsWith(".tgz"))
      : null;
    if (!archive) {
      absent += 1;
      continue;
    }
    const body = fs.readFileSync(path.join(dir, archive));
    const declared = declaredCoordinate(body);
    if (!declared || declared.name !== target.name || declared.version !== target.version) {
      process.stderr.write(`rejected ${target.name}@${target.version}: archive declares ` +
        `${declared ? `${declared.name}@${declared.version}` : "nothing readable"}\n`);
      rejected += 1;
      continue;
    }
    const dist = registryMetadata(dir)?.dist;
    const verification = verify(body, dist);
    if (verification.status === "mismatch") {
      process.stderr.write(`rejected ${target.name}@${target.version}: ${verification.basis[0]}\n`);
      rejected += 1;
      continue;
    }

    const digest = crypto.createHash("sha256").update(body).digest("hex");
    process.stderr.write(`${verification.status} ${target.name}@${target.version} sha256:${digest.slice(0, 12)}\n`);
    ingested += 1;
    if (options.dryRun) continue;

    const filename = `${safeSegment(target.name.replace(/^@/, "").replace("/", "-"))}-${safeSegment(target.version)}.tgz`;
    const destinationDir = path.join(target.attackDir, "samples", safeSegment(target.artifactId), "during");
    fs.mkdirSync(destinationDir, { recursive: true });
    const destination = path.join(destinationDir, filename);
    if (fs.existsSync(destination)) fs.chmodSync(destination, 0o644);
    fs.writeFileSync(destination, body);
    const originalURL = dist?.tarball ||
      `https://registry.npmjs.org/${encodeName(target.name)}/-/${target.name.split("/").at(-1)}-${target.version}.tgz`;
    fs.writeFileSync(`${destination}.forage.json`, `${JSON.stringify({
      schema_version: "1.0",
      artifact: { filename, sha256: digest, size_bytes: body.length },
      package: {
        ecosystem: "npm", name: target.name, version: target.version,
        purl: `pkg:npm/${encodeName(target.name)}@${encodeURIComponent(target.version)}`,
      },
      fetch: {
        collector: "research-corpus-ingest",
        category: "research_corpus",
        at: new Date().toISOString(),
        url: `corpus://${CORPUS_NAME}/npm/${target.name}/${target.version}/${archive}`,
        original_url: originalURL,
        derivation: [
          `Held by ${CORPUS_NAME}, which keeps the published tarball of a malicious release with the registry metadata that described it.`,
          verification.status === "exact"
            ? "The archive reproduces the dist digest npm published for this version, so these are the bytes the registry served."
            : "The corpus stored no registry digest for this version, so the bytes are the corpus's copy of the published archive rather than a digest-bound one.",
        ],
      },
    }, null, 2)}\n`);
    fs.chmodSync(destination, 0o444);

    const stored = compressLargeSample(destination);
    if (!manifests.has(target.manifestFile)) {
      manifests.set(target.manifestFile, fs.existsSync(target.manifestFile)
        ? yaml.load(fs.readFileSync(target.manifestFile, "utf8")) || { schema_version: 1, samples: [], unresolved: [] }
        : { schema_version: 1, samples: [], unresolved: [] });
    }
    const manifest = manifests.get(target.manifestFile);
    manifest.samples ||= [];
    manifest.unresolved ||= [];
    const coordinate = `pkg:npm/${encodeName(target.name)}@${encodeURIComponent(target.version)}`;
    const key = entry => `${entry.artifact_id} ${entry.phase} ${String(entry.coordinate || "").split("?", 1)[0]}`;
    const entry = {
      artifact_id: target.artifactId,
      phase: "during",
      classification: "affected",
      coordinate,
      version: target.version,
      filename,
      path: path.relative(path.join(target.attackDir, "samples"), stored.path),
      sha256: digest,
      size: body.length,
      source: {
        url: `corpus://${CORPUS_NAME}/npm/${target.name}/${target.version}/${archive}`,
        original_url: originalURL,
        retrieved_at: new Date().toISOString(),
        kind: "research_corpus",
      },
      ...(stored.storage ? { storage: stored.storage } : {}),
      verification: { status: verification.status, basis: [...verification.basis, "exact_package_name_and_version", "measured_sha256"] },
      notes: [`Recovered from ${CORPUS_NAME}, which retained the published archive after npm removed it.`],
    };
    manifest.samples = manifest.samples.filter(x => key(x) !== key(entry));
    manifest.unresolved = manifest.unresolved.filter(x => key(x) !== key(entry));
    manifest.samples.push(entry);
  }

  if (!options.dryRun) {
    for (const [file, manifest] of manifests) {
      fs.writeFileSync(file, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
    }
  }
  process.stderr.write(`\n${ingested} ingested, ${absent} not in the corpus, ${rejected} rejected\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
}
