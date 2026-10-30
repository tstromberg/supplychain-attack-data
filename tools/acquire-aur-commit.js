#!/usr/bin/env node

/*
 * Recovers a deleted AUR package state from the archlinux/aur GitHub mirror.
 *
 * When a malicious AUR commit is found, Arch resets the package's history: the commit
 * stops being reachable, cgit answers 404 for it, and an upload-pack request for the
 * id is refused with "not our ref". The Arch DevOps team also publishes a continuous
 * mirror of every AUR repository to github.com/archlinux/aur, and GitHub keeps a
 * commit it has once received even after the ref that carried it is gone. So the
 * commit the sanitized history no longer admits is still addressable by id there,
 * with its full tree.
 *
 * Every file is checked against the git blob id the commit's own tree names. That is
 * self-verifying: a blob id is SHA-1 over "blob <size>\0" and the content, so matching
 * it proves the bytes are the ones the recorded commit contained, independently of
 * what the mirror claims to be serving.
 *
 *   node tools/acquire-aur-commit.js --incident arch-aur-august-2026 \
 *     --artifact openconnect-sso --commit 9d107786fa851c6305dadb3573aab5330a041524
 *
 * Requires an authenticated `gh`; the mirror is large and the API is rate limited.
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const yaml = require("js-yaml");
const { verificationFrom } = require("./normalize-basis.js");
const provenance = require("./provenance-store.js");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];
const MIRROR = "archlinux/aur";

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/acquire-aur-commit.js --incident ID --artifact ID --commit SHA [options]\n\n` +
    `  --incident ID     Incident directory name, e.g. arch-aur-august-2026\n` +
    `  --artifact ID     Artifact id the recovered files belong to\n` +
    `  --package NAME    Store under <artifact>/<phase>/<package>/, for an artifact that\n` +
    `                    stands for many packages rather than one\n` +
    `  --commit SHA      The removed commit, as published by the incident report\n` +
    `  --phase PHASE     during (default) or before\n` +
    `  --dry-run         Report the tree and stop\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = { phase: "during" };
  for (let i = 2; i < argv.length; i += 1) {
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) usage(1);
      i += 1;
      return next;
    };
    const arg = argv[i];
    if (arg === "--incident") options.incident = value();
    else if (arg === "--artifact") options.artifact = value();
    else if (arg === "--package") options.package = value();
    else if (arg === "--commit") options.commit = value().toLowerCase();
    else if (arg === "--phase") options.phase = value();
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--help" || arg === "-h") usage(0);
    else usage(1);
  }
  if (!options.incident || !options.artifact || !/^[0-9a-f]{40}$/.test(options.commit || "")) usage(1);
  return options;
}

function gh(endpoint) {
  const out = execFileSync("gh", ["api", endpoint], { maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(out.toString());
}

function attackDir(incident) {
  for (const scope of SCOPES) {
    const dir = path.join(scope, incident);
    if (fs.existsSync(path.join(dir, "meta.yaml"))) return dir;
  }
  throw new Error(`no record directory for incident ${incident}`);
}

// Every SHA-256 the record states anywhere for this artifact, so a recovered file that
// matches one can be recorded as exact rather than merely mirror-sourced. Reports state
// these both as artifact hashes and, for payload members, inside incident indicators.
function reportedDigests(dir, artifactId) {
  const digests = new Set();
  const records = yaml.load(fs.readFileSync(path.join(dir, "meta.yaml"), "utf8"));
  for (const record of Array.isArray(records) ? records : [records]) {
    for (const indicator of record.indicators || []) {
      for (const found of String(indicator.value || "").matchAll(/\b[a-f0-9]{64}\b/g)) digests.add(found[0]);
    }
    for (const artifact of record.artifacts || []) {
      if (artifact.id !== artifactId) continue;
      for (const hash of artifact.hashes || []) {
        const value = typeof hash === "string" ? hash.replace(/^sha256:/, "") : String(hash.sha256 || "");
        if (/^[a-f0-9]{64}$/.test(value)) digests.add(value);
      }
    }
  }
  return digests;
}

function gitBlobId(content) {
  return crypto.createHash("sha1").update(`blob ${content.length}\0`).update(content).digest("hex");
}

function loadManifest(file) {
  if (!fs.existsSync(file)) return { schema_version: 1, samples: [], unresolved: [] };
  const value = yaml.load(fs.readFileSync(file, "utf8")) || {};
  value.samples ||= [];
  value.unresolved ||= [];
  return value;
}

function main() {
  const options = parseArgs(process.argv);
  const dir = attackDir(options.incident);
  const commit = gh(`repos/${MIRROR}/commits/${options.commit}`);
  if (commit.sha !== options.commit) throw new Error(`mirror returned ${commit.sha} for ${options.commit}`);
  const tree = gh(`repos/${MIRROR}/git/trees/${commit.commit.tree.sha}?recursive=1`);
  if (tree.truncated) throw new Error("tree listing truncated; this package is too large for one request");

  const files = tree.tree.filter(entry => entry.type === "blob");
  process.stderr.write(`${MIRROR} ${options.commit.slice(0, 12)} "${commit.commit.message.split("\n")[0]}" ` +
    `by ${commit.commit.author.name} on ${commit.commit.author.date}: ${files.length} files\n`);
  for (const file of files) process.stderr.write(`  ${file.path} (${file.size} bytes)\n`);
  if (options.dryRun) return;

  const reported = reportedDigests(dir, options.artifact);
  // An aggregate artifact stands for a whole wave of packages, and every AUR package
  // has a PKGBUILD and a .SRCINFO. Without a directory per package they overwrite each
  // other and the artifact ends up holding one arbitrary package's files.
  const destinationDir = path.join(dir, "samples", options.artifact, options.phase,
    ...(options.package ? [options.package] : []));
  fs.mkdirSync(destinationDir, { recursive: true });
  const manifestFile = path.join(dir, "samples", "manifest.yaml");
  const manifest = loadManifest(manifestFile);
  const retrievedAt = new Date().toISOString();

  for (const file of files) {
    const blob = gh(`repos/${MIRROR}/git/blobs/${file.sha}`);
    const content = Buffer.from(blob.content, blob.encoding === "base64" ? "base64" : "utf8");
    if (gitBlobId(content) !== file.sha) throw new Error(`${file.path}: blob id mismatch, refusing to store`);
    const digest = crypto.createHash("sha256").update(content).digest("hex");
    let name = path.basename(file.path);
    // A member name can already be held with different bytes: the same payload file
    // appears in several waves of these campaigns under one name. Keep both, so a
    // recovery never overwrites evidence that was acquired another way.
    if (fs.existsSync(path.join(destinationDir, name)) &&
        crypto.createHash("sha256").update(fs.readFileSync(path.join(destinationDir, name))).digest("hex") !== digest) {
      name = `${name}-${digest.slice(0, 12)}`;
    }
    const destination = path.join(destinationDir, name);
    // Stored samples are read-only, so a rerun has to lift that before rewriting.
    if (fs.existsSync(destination)) fs.chmodSync(destination, 0o644);
    fs.writeFileSync(destination, content);
    fs.chmodSync(destination, 0o444);

    const url = `https://github.com/${MIRROR}/raw/${options.commit}/${file.path}`;
    provenance.record(path.join(dir, "samples"), digest, content.length, {
      schema_version: "1.0",
      artifact: { filename: name, sha256: digest, size_bytes: content.length },
      package: {
        ecosystem: "aur",
        name: options.package || options.artifact,
        purl: `pkg:alpm/aur/${options.package || options.artifact}`,
      },
      fetch: {
        collector: "aur-mirror-recovery",
        category: "removed_git_history",
        at: retrievedAt,
        url,
        derivation: [
          `Member of AUR commit ${options.commit}, which the sanitized aur.archlinux.org history no longer serves.`,
          `The archlinux/aur GitHub mirror still holds the commit; the bytes reproduce the git blob id ${file.sha} the commit's tree names.`,
        ],
      },
    });

    // The package belongs in the key. Without it every package's PKGBUILD and .SRCINFO
    // share a key with every other package's, so each recovery evicts the previous
    // package's rows and only the uniquely-named payload survives in the manifest.
    const key = entry => [entry.artifact_id, entry.phase, entry.package || "", entry.filename].join("\u0000");
    const entry = {
      artifact_id: options.artifact,
      phase: options.phase,
      ...(options.package ? { package: options.package } : {}),
      classification: options.phase === "during" ? "malicious" : "clean",
      filename: name,
      path: path.relative(path.join(dir, "samples"), destination),
      sha256: digest,
      size: content.length,
      source: { url, retrieved_at: retrievedAt, kind: "removed_git_history" },
      verification: reported.has(digest)
        ? verificationFrom("exact", ["reported_sha256", "git_blob_id_verified", "measured_sha256"])
        : verificationFrom("exact", ["git_blob_id_verified", "measured_sha256"]),
      notes: [`Recovered from AUR commit ${options.commit}${options.package ? ` on the ${options.package} package` : ""} ` +
        `through the archlinux/aur mirror, which retains commits the AUR history was reset past.`],
    };
    manifest.samples = manifest.samples.filter(x => key(x) !== key(entry));
    manifest.samples.push(entry);
    process.stderr.write(`stored ${name} sha256:${digest}${reported.has(digest) ? " (matches a reported digest)" : ""}\n`);
  }

  fs.writeFileSync(manifestFile, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
  // Whether this recovery closes an unresolved record is a judgement about what the
  // record was claiming, not something a file count settles: recovering a commit's tree
  // can still leave a separately reported archive missing. Existing entries are left for
  // an operator to retire or narrow by hand.
  const open = (manifest.unresolved || []).filter(x => x.artifact_id === options.artifact && x.phase === options.phase);
  if (open.length) process.stderr.write(`\n${open.length} unresolved record(s) for ${options.artifact}/${options.phase} still stand; review them against what was recovered.\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`acquire-aur-commit: ${error.message}\n`);
  process.exitCode = 1;
}
