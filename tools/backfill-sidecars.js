#!/usr/bin/env node
"use strict";

/*
 * Writes the provenance record for a sample that was added by hand.
 *
 *   node tools/backfill-sidecars.js [--only ID] [--dry-run]
 *
 * Every sample needs a capture record in samples/provenance/<sha256>.json, and
 * `make samples-verify` refuses a sample without one. A file fetched or built by hand arrives without that record even
 * when the manifest entry is complete, so this rebuilds it from what the manifest
 * already states rather than asking anyone to hand-write JSON.
 *
 * Nothing is invented. The record repeats the manifest's own source block, and for a
 * reconstruction it repeats the reconstruction chain and says plainly that the digest
 * identifies the synthetic container rather than the archive the registry served. A
 * sample whose bytes disagree with the manifest is skipped and reported, because a
 * mismatch means the manifest or the file is wrong and a generated sidecar would only
 * paper over it. An existing record is never overwritten: capture-time evidence is
 * frozen, and a later rebuild must not rewrite what was recorded when the bytes landed.
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..");
const provenance = require("./provenance-store.js");

function parseArgs(argv) {
  const options = { only: "", dryRun: false };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--only") options.only = argv[++i] || "";
    else if (argv[i] === "--dry-run") options.dryRun = true;
    else {
      process.stderr.write(`unknown argument: ${argv[i]}\n`);
      process.exit(2);
    }
  }
  return options;
}

function walkManifests(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walkManifests(file, out);
    else if (entry.name === "manifest.yaml" && path.basename(path.dirname(file)) === "samples") out.push(file);
  }
  return out;
}

const sha256 = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

// The container an artifact is stored in is not the artifact. A compressed sample's
// sidecar is keyed on the artifact's own name, so strip the storage extension.
function artifactName(sample) {
  const base = path.basename(sample.path);
  return sample.storage?.format === "xz" && base.endsWith(".xz") ? base.slice(0, -3) : base;
}

function ecosystemOf(coordinate) {
  const match = /^pkg:([a-z-]+)\//.exec(String(coordinate || ""));
  if (!match) return "";
  return { npm: "javascript", pypi: "python", composer: "php", gem: "ruby" }[match[1]] || match[1];
}

function buildSidecar(sample, measured, size) {
  const source = sample.source || {};
  const reconstruction = source.reconstruction;
  const doc = {
    schema_version: "1.0",
    artifact: { filename: artifactName(sample), sha256: measured, size_bytes: size },
    package: {
      ecosystem: ecosystemOf(sample.coordinate),
      name: sample.artifact_id,
      version: sample.version || "",
      purl: sample.coordinate || "",
      feed: reconstruction ? "manual-reconstruction" : "manual-acquisition",
    },
    fetch: {
      collector: reconstruction ? "manual-reconstruction" : "manual-acquisition",
      category: sample.classification === "clean" || sample.classification === "remediated" ? "good" : "malicious",
      at: source.retrieved_at || new Date().toISOString(),
      url: source.url || "",
    },
  };
  if (source.original_url) doc.fetch.original_url = source.original_url;
  if (reconstruction) {
    doc.provenance = {
      qualification: "Synthetic reconstruction; no authoritative whole-archive digest is available for the removed upstream file, so this digest identifies the synthetic container rather than what the distribution channel served.",
      ...reconstruction,
      verification_basis: (sample.verification || {}).basis,
    };
  } else {
    doc.provenance = {
      qualification: "Acquired by hand from the source recorded in the incident manifest; this digest was measured from the stored bytes.",
      source_kind: source.kind || "",
      verification_status: (sample.verification || {}).status,
      verification_basis: (sample.verification || {}).basis,
    };
  }
  return doc;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  let written = 0, skipped = 0, mismatched = 0, absent = 0;

  for (const root of ["oss", "proprietary"]) {
    for (const manifestFile of walkManifests(path.join(ROOT, root))) {
      const dir = path.dirname(manifestFile);
      const recordId = path.basename(path.dirname(dir));
      if (options.only && recordId !== options.only) continue;

      let manifest;
      try { manifest = yaml.load(fs.readFileSync(manifestFile, "utf8")) || {}; } catch (_) { continue; }

      for (const sample of manifest.samples || []) {
        if (!sample.path) continue;
        const file = path.resolve(dir, sample.path);
        if (!fs.existsSync(file)) { absent += 1; continue; }

        // Provenance is filed under the artifact's digest, so it survives a re-phase.
        const sidecar = provenance.provenanceFile(dir, sample.sha256);
        if (fs.existsSync(sidecar)) { skipped += 1; continue; }

        // A compressed sample's stored digest differs from the artifact digest, and
        // rebuilding that pairing is not this tool's job.
        if (sample.storage) { skipped += 1; continue; }

        const measured = sha256(file);
        if (measured !== sample.sha256) {
          mismatched += 1;
          process.stderr.write(`${recordId}: ${sample.path} measured ${measured} != manifest ${sample.sha256}\n`);
          continue;
        }

        const doc = buildSidecar(sample, measured, fs.statSync(file).size);
        if (!options.dryRun) provenance.record(dir, measured, fs.statSync(file).size, doc);
        written += 1;
        process.stdout.write(`${recordId}: ${path.basename(sidecar)}\n`);
      }
    }
  }
  process.stdout.write(`${options.dryRun ? "would write" : "wrote"} ${written}; already present ${skipped}; digest mismatch ${mismatched}; file absent ${absent}\n`);
  if (mismatched) process.exitCode = 1;
}

main();
