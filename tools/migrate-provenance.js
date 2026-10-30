#!/usr/bin/env node

/*
 * Move the `<sample>.forage.json` sidecars into the digest-keyed provenance store.
 *
 * See tools/provenance-store.js for why the store is keyed on the digest rather than on
 * the path. This is the one-time move, and it is conservative in three ways:
 *
 *   - an acquisition is copied verbatim, never reshaped;
 *   - identical acquisitions of the same bytes collapse, different ones accumulate;
 *   - a sidecar whose digest no manifest claims is reported and left where it is,
 *     because an orphan is usually the trace of a rename that half-finished, and
 *     deleting it would destroy the only evidence of what happened.
 *
 *   node tools/migrate-provenance.js            report only
 *   node tools/migrate-provenance.js --apply    write the store and remove the sidecars
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");
const store = require("./provenance-store.js");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];

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

function sidecarsUnder(dir, found = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "provenance") sidecarsUnder(file, found);
    } else if (entry.name.endsWith(".forage.json")) found.push(file);
  }
  return found;
}

function main() {
  const apply = process.argv.includes("--apply");
  let moved = 0;
  let merged = 0;
  let files = 0;
  let noSidecar = 0;
  let auxiliary = 0;
  const orphans = [];
  const unreadable = [];
  const missing = [];

  for (const dir of records()) {
    const samplesDir = path.join(dir, "samples");
    const manifest = yaml.load(fs.readFileSync(path.join(samplesDir, "manifest.yaml"), "utf8")) || {};

    // The manifest is the authority on which bytes the record holds, so the store is built
    // from it and the sidecars are consulted, not trusted.
    const claimed = new Map();   // absolute sidecar path -> sample
    const sizes = new Map();     // digest -> size
    for (const sample of manifest.samples || []) {
      if (!sample.sha256) continue;
      sizes.set(String(sample.sha256), sample.size);
      const stored = path.resolve(path.join(samplesDir, String(sample.path || "")));
      /*
       * Two conventions have to be accepted. A sample can carry a second record from a
       * later verification pass, and a sample held xz-compressed keeps its record under
       * the artifact's own name rather than the container's -- provenance describes the
       * bytes that were fetched, not how the repository chose to store them.
       */
      for (const base of new Set([stored, stored.replace(/\.xz$/, "")])) {
        claimed.set(`${base}.forage.json`, sample);
        claimed.set(`${base}.verification.forage.json`, sample);
      }
    }

    const documents = new Map();   // digest -> document
    const consumed = [];

    for (const file of sidecarsUnder(samplesDir)) {
      const sample = claimed.get(path.resolve(file));
      if (!sample) {
        /*
         * A sidecar whose base file is on disk but is not a manifest sample describes an
         * auxiliary artifact -- a `.partial.json` member listing beside a reconstruction,
         * say. The store is for samples, so it stays with the file it documents.
         */
        const base = file.replace(/\.forage\.json$/, "");
        if (fs.existsSync(base)) auxiliary += 1;
        else orphans.push(path.relative(ROOT, file));
        continue;
      }
      let acquisition;
      try {
        acquisition = JSON.parse(fs.readFileSync(file, "utf8"));
      } catch (error) {
        unreadable.push(`${path.relative(ROOT, file)}: ${error.message}`);
        continue;
      }
      const digest = String(sample.sha256);
      const before = documents.get(digest);
      const after = store.add(before, digest, sizes.get(digest), acquisition);
      documents.set(digest, after);
      if (before && after.acquisitions.length === before.acquisitions.length) merged += 1;
      moved += 1;
      consumed.push(file);
    }

    for (const sample of manifest.samples || []) {
      if (!sample.sha256) continue;
      // Already migrated counts as covered: a second run finds no sidecars to read, and
      // must not report every sample in the corpus as having lost its provenance.
      if (fs.existsSync(store.provenanceFile(samplesDir, sample.sha256))) continue;
      if (!documents.has(String(sample.sha256))) {
        noSidecar += 1;
        if (missing.length < 10) {
          missing.push(`${path.relative(ROOT, dir)} ${sample.subject}/${sample.phase}/${sample.filename}`);
        }
      }
    }

    if (!apply) {
      files += documents.size;
      continue;
    }
    for (const doc of documents.values()) {
      store.write(samplesDir, doc);
      files += 1;
    }
    for (const file of consumed) fs.rmSync(file);
  }

  const out = process.stdout;
  out.write(`${moved} sidecar(s) read into ${files} digest-keyed document(s)\n`);
  out.write(`  identical acquisitions collapsed: ${merged}\n`);
  out.write(`  samples with no provenance at all: ${noSidecar}\n`);
  for (const item of missing) out.write(`      ${item}\n`);
  out.write(`  records for auxiliary files, left: ${auxiliary}\n`);
  out.write(`  orphan sidecars left in place:    ${orphans.length}\n`);
  for (const item of orphans.slice(0, 10)) out.write(`      ${item}\n`);
  if (orphans.length > 10) out.write(`      … ${orphans.length - 10} more\n`);
  if (unreadable.length) {
    out.write(`  unreadable: ${unreadable.length}\n`);
    for (const item of unreadable.slice(0, 5)) out.write(`      ${item}\n`);
  }
  out.write(apply ? "\nwrote the store and removed the sidecars it consumed\n"
                  : "\nreport only; pass --apply to write\n");
}

try {
  main();
} catch (error) {
  process.stderr.write(`migrate-provenance: ${error.stack || error.message}\n`);
  process.exitCode = 1;
}
