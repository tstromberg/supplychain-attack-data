#!/usr/bin/env node

/*
 * Removes the generated evidence-record stubs that stand in for samples nobody has.
 *
 * These files were written to fill an empty sample slot, and they say what they are:
 * "This is not a recovered payload", "recovery_status = no exact payload bytes
 * recovered in the current corpus", and, in their manifest note, "the unresolved
 * record remains authoritative". They carry no evidence — the sha256 recorded for one
 * is the digest of the stub itself.
 *
 * Keeping them is not neutral. A slot that looks filled stops being asked about: the
 * closed-source lane reported 163 of 163 artifacts acquired while 117 of its samples
 * were stubs, and every tool that answers "do we have this yet" has to be taught to
 * ignore them, one tool at a time, forever. Deleting them is the version of that fix
 * which cannot be forgotten by the next tool.
 *
 * What must not be lost is the fact that the slot is empty and was attempted, so each
 * removal leaves an unresolved record behind where the manifest has none.
 *
 * A file is only removed when its own bytes match the generated template. Naming and
 * source.kind are how candidates are found; content is what authorises the delete.
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");
const provenance = require("./provenance-store.js");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];

// Every line the generator emits that asserts the file is not evidence. All must be
// present, so a real sample that happens to be named like one is never deleted.
const TEMPLATE_MARKERS = [
  "This is not a recovered payload",
  "recovery_status = no exact payload bytes recovered in the current corpus",
  "scope = payload_only evidence record",
];

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/remove-placeholder-samples.js [options]\n\n` +
    `  --dry-run   Report what would be removed and stop\n` +
    `  --help\n`);
  process.exit(exitCode);
}

// Manifests live at <incident>/samples/manifest.yaml, but a few incidents nest a year
// or a wave below the directory, so the tree is walked rather than listed.
function manifests(dir, found = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const child = path.join(dir, entry.name);
    if (!entry.isDirectory()) continue;
    if (entry.name === "samples") {
      const file = path.join(child, "manifest.yaml");
      if (fs.existsSync(file)) found.push(file);
      continue;
    }
    if (entry.name === "refs") continue;
    manifests(child, found);
  }
  return found;
}

// The generator has been run under two source kinds. Both write the same file, and one
// of them also stamps version: metadata-backed-evidence, so the kind is a hint and the
// content below is the authority.
const STUB_KINDS = new Set(["metadata_backed_evidence_record", "event_metadata"]);

function isPlaceholder(samplesDir, sample) {
  if (!String(sample.filename || "").endsWith("-evidence.fragment")) return false;
  if (!STUB_KINDS.has(String(sample.source?.kind || ""))) return false;
  const file = path.join(samplesDir, String(sample.path || ""));
  if (!fs.existsSync(file)) return false;
  const body = fs.readFileSync(file, "utf8");
  return TEMPLATE_MARKERS.every(marker => body.includes(marker));
}

/*
 * unresolvedFor is what the removal leaves behind. The stub's own note says the
 * unresolved record is authoritative, so where one exists the stub adds nothing and
 * only the file goes; where none exists, one is written from what the stub recorded.
 */
function unresolvedFor(sample) {
  const entry = {
    artifact_id: sample.artifact_id,
    phase: sample.phase,
    status: "no_payload_bytes_recovered",
  };
  if (sample.coordinate) entry.coordinate = sample.coordinate;
  if (sample.version) entry.version = sample.version;
  entry.attempts = [
    "A generated evidence-record stub occupied this sample slot until 2026-09-10. It held no " +
    "payload: its stated recovery_status was \"no exact payload bytes recovered in the current " +
    "corpus\" and its own note deferred to the unresolved record. The stub was removed so the " +
    "slot reads as empty to every tool that asks, and this record replaces it.",
  ];
  return entry;
}

function main() {
  let dryRun = false;
  for (const arg of process.argv.slice(2)) {
    if (arg === "--dry-run") dryRun = true;
    else if (arg === "--help" || arg === "-h") usage(0);
    else usage(1);
  }

  let removed = 0;
  let recordsAdded = 0;
  let manifestsTouched = 0;

  for (const scope of SCOPES) {
    for (const manifestFile of manifests(scope)) {
      const samplesDir = path.dirname(manifestFile);
      const manifest = yaml.load(fs.readFileSync(manifestFile, "utf8")) || {};
      const stubs = (manifest.samples || []).filter(sample => isPlaceholder(samplesDir, sample));
      if (stubs.length === 0) continue;

      manifest.unresolved ||= [];
      for (const stub of stubs) {
        const covered = manifest.unresolved.some(x =>
          x.artifact_id === stub.artifact_id && x.phase === stub.phase);
        process.stdout.write(`${path.relative(ROOT, path.join(samplesDir, stub.path))}` +
          `${covered ? "" : "  (+ unresolved record)"}\n`);
        if (dryRun) {
          removed += 1;
          if (!covered) recordsAdded += 1;
          continue;
        }
        const file = path.join(samplesDir, stub.path);
        if (fs.existsSync(file)) {
          fs.chmodSync(file, 0o644);
          fs.rmSync(file);
        }
        /*
         * The acquisition record goes only when nothing else in the record holds these
         * bytes. A placeholder frequently shares a digest with a real sample, and a
         * provenance document describes bytes rather than the entry that pointed at them.
         */
        const alsoHeld = (manifest.samples || [])
          .some(x => x !== stub && !stubs.includes(x) && x.sha256 === stub.sha256);
        if (stub.sha256 && !alsoHeld) {
          const document = provenance.provenanceFile(samplesDir, stub.sha256);
          if (fs.existsSync(document)) fs.rmSync(document);
        }
        // A stub is the only thing in its phase directory whenever it was the only
        // sample; leave nothing behind that reads as a half-populated slot.
        const phaseDir = path.dirname(path.join(samplesDir, stub.path));
        if (fs.existsSync(phaseDir) && fs.readdirSync(phaseDir).length === 0) fs.rmdirSync(phaseDir);
        const artifactDir = path.dirname(phaseDir);
        if (fs.existsSync(artifactDir) && fs.readdirSync(artifactDir).length === 0) fs.rmdirSync(artifactDir);

        if (!covered) {
          manifest.unresolved.push(unresolvedFor(stub));
          recordsAdded += 1;
        }
        removed += 1;
      }

      if (dryRun) continue;
      manifest.samples = (manifest.samples || []).filter(sample => !stubs.includes(sample));
      fs.writeFileSync(manifestFile, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
      manifestsTouched += 1;
    }
  }

  process.stderr.write(`\n${removed} stub${removed === 1 ? "" : "s"} ` +
    `${dryRun ? "would be removed" : "removed"} across ${manifestsTouched} manifest(s); ` +
    `${recordsAdded} unresolved record(s) ${dryRun ? "would be " : ""}added\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`remove-placeholder-samples: ${error.message}\n`);
  process.exitCode = 1;
}
