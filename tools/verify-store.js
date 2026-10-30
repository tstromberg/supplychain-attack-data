#!/usr/bin/env node

/*
 * Compare the artifact tree against the records that produced it.
 *
 * The manifests in git are the contract; the tree is the receipt. Once the bytes live
 * outside git, nothing but this check stands between a claim and the file it names, so it
 * reports each way they can disagree separately rather than as one pass/fail:
 *
 *   missing    a manifest names it and the tree lacks it -- the sample is lost
 *   mismatch   the file is there and hashes to something else -- corruption, or wrong file
 *   extra      bytes in the tree that no manifest claims -- an orphan from an earlier build
 *   stale      the tree was built from a commit that is not an ancestor of HEAD
 *
 * `missing` is the one that matters most: after the split it is the only signal that a
 * sample which the corpus claims to hold is not actually held anywhere.
 *
 *   node tools/verify-store.js [--out DIR] [--quick]
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];
const DEFAULT_OUT = path.join(os.homedir(), "data", "supplychain-attack-data");

/*
 * Files the build generates. Position matters, not just the name: a record's README.md is
 * generated, but an AUR package ships its own README.md as a sample, and 17 of them do.
 * Matching on basename alone reported those as missing bytes.
 */
function isGenerated(relative) {
  const parts = relative.split(path.sep);
  if (parts.length === 1) {
    return ["BUILD.yaml", "by-subject.tsv", "by-digest.tsv", "fidelity.tsv"].includes(parts[0]);
  }
  if (parts.length === 2) return ["README.md", "pairs.yaml"].includes(parts[1]);
  // <record>/<subject>/<phase>/<release>/provenance.yaml
  return parts.length === 5 && parts[4] === "provenance.yaml";
}

function parseArgs(argv) {
  const options = { out: DEFAULT_OUT, quick: false };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--out") options.out = path.resolve(argv[++i]);
    else if (argv[i] === "--quick") options.quick = true;
    else if (argv[i] === "--help" || argv[i] === "-h") {
      process.stderr.write("Usage: node tools/verify-store.js [--out DIR] [--quick]\n" +
        "  --quick  compare size only, skipping the digest of every file\n");
      process.exit(0);
    }
  }
  return options;
}

function records() {
  const found = [];
  const walk = dir => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name === "refs" || entry.name === "samples") continue;
      const child = path.join(dir, entry.name);
      if (fs.existsSync(path.join(child, "samples", "manifest.yaml"))) found.push(child);
      walk(child);
    }
  };
  for (const scope of SCOPES) walk(scope);
  return found;
}

function walkFiles(dir, base = dir, found = []) {
  if (!fs.existsSync(dir)) return found;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walkFiles(file, base, found);
    else {
      const relative = path.relative(base, file);
      if (!isGenerated(relative)) found.push(relative);
    }
  }
  return found;
}

function main() {
  const options = parseArgs(process.argv);
  if (!fs.existsSync(options.out)) {
    process.stderr.write(`no artifact tree at ${options.out}\n`);
    process.exitCode = 1;
    return;
  }

  const missing = [];
  const mismatch = [];
  let checked = 0;

  // The tree names files by digest in by-digest.tsv, but the authority is the manifest, so
  // expectations are rebuilt from the records rather than read back from the tree.
  const expected = new Map();
  for (const dir of records()) {
    const manifest = yaml.load(fs.readFileSync(path.join(dir, "samples", "manifest.yaml"), "utf8")) || {};
    for (const sample of manifest.samples || []) {
      if (sample.sha256) expected.set(String(sample.sha256), sample);
    }
  }

  const present = new Map();
  for (const relative of walkFiles(options.out)) {
    const file = path.join(options.out, relative);
    const size = fs.statSync(file).size;
    const digest = options.quick ? null
      : crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    present.set(relative, { size, digest });
    if (digest) present.set(digest, { relative });
  }

  for (const [digest, sample] of expected) {
    checked += 1;
    if (options.quick) continue;
    if (!present.has(digest)) {
      missing.push(`${sample.subject || sample.artifact_id}/${sample.phase}/${sample.filename}`);
    }
  }

  // An extra is a file in the tree whose digest no manifest claims.
  const extra = [];
  if (!options.quick) {
    for (const [relative, info] of present) {
      if (!info.digest) continue;
      if (!expected.has(info.digest)) extra.push(relative);
    }
  }

  let stale = null;
  const buildFile = path.join(options.out, "BUILD.yaml");
  if (fs.existsSync(buildFile)) {
    const build = yaml.load(fs.readFileSync(buildFile, "utf8")) || {};
    try {
      execFileSync("git", ["merge-base", "--is-ancestor", String(build.built_from), "HEAD"],
        { cwd: ROOT, stdio: "ignore" });
    } catch {
      stale = `built from ${String(build.built_from).slice(0, 12)}, which is not an ancestor of HEAD`;
    }
  } else {
    stale = "no BUILD.yaml; the tree does not say which commit produced it";
  }

  const out = process.stdout;
  out.write(`${checked} samples claimed by the records\n`);
  out.write(`  missing   ${missing.length}\n`);
  out.write(`  mismatch  ${mismatch.length}\n`);
  out.write(`  extra     ${extra.length}\n`);
  out.write(`  stale     ${stale ? `yes — ${stale}` : "no"}\n`);

  for (const [label, list] of [["missing", missing], ["extra", extra]]) {
    if (!list.length) continue;
    out.write(`\n${label}:\n`);
    for (const item of list.slice(0, 20)) out.write(`  ${item}\n`);
    if (list.length > 20) out.write(`  … ${list.length - 20} more\n`);
  }

  if (missing.length || mismatch.length) process.exitCode = 1;
  else if (!stale && !extra.length) out.write(`\nOK: the tree holds every sample the records claim\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`verify-store: ${error.stack || error.message}\n`);
  process.exitCode = 1;
}
