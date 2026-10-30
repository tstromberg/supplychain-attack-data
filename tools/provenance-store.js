#!/usr/bin/env node

/*
 * Where a record keeps its acquisition history.
 *
 * Provenance is a fact about bytes: who fetched them, from what URL, when, and with what
 * collector. None of that changes when the corpus decides a sample was misfiled, but for
 * as long as the record lived beside the sample, every such decision moved it. That churn
 * is real -- one session re-phased 754 samples and renamed several artifact ids, dragging
 * a sidecar along each time, and a rename that fails halfway separates bytes from their
 * history permanently.
 *
 * So the store is keyed on the digest:
 *
 *   <record>/samples/provenance/<sha256>.json
 *
 * One consequence is worth stating plainly, because it is a change in meaning rather than
 * in filing. The same bytes are frequently acquired more than once -- one `.gitignore` is
 * byte-identical across eight AUR packages, each fetched from its own git path -- and 549
 * of the 574 duplicate-digest groups in the corpus carry genuinely different acquisition
 * records. A digest-keyed file that held one of them would throw the rest away. So the
 * file holds a list, and each acquisition is stored exactly as the collector wrote it:
 *
 *   { schema_version, sha256, size_bytes, acquisitions: [ <collector record>, … ] }
 *
 * Nothing here interprets an acquisition. The shapes vary a great deal -- 37 distinct
 * top-level keys across the corpus, from a bare fetch to a full reconstruction record --
 * and a store that parsed them would have to be revised every time a new collector
 * appeared. It compares them, and that is all.
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");

const SCHEMA_VERSION = 2;

function provenanceFile(samplesDir, sha256) {
  return path.join(samplesDir, "provenance", `${String(sha256)}.json`);
}

function read(samplesDir, sha256) {
  const file = provenanceFile(samplesDir, sha256);
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/*
 * The filename an artifact happened to be stored under is a property of the path, not of
 * the bytes, and it is the one field that differs between otherwise identical acquisitions
 * of the same file. Comparing without it is what lets 25 redundant copies collapse while
 * 549 genuinely distinct fetches survive.
 */
function identity(acquisition) {
  const copy = JSON.parse(JSON.stringify(acquisition));
  if (copy.artifact) {
    delete copy.artifact.filename;
    delete copy.artifact.sha256;
    delete copy.artifact.size_bytes;
    if (!Object.keys(copy.artifact).length) delete copy.artifact;
  }
  return JSON.stringify(copy);
}

// add records one acquisition of these bytes, returning the merged document. An
// acquisition already present is not repeated.
function add(existing, sha256, sizeBytes, acquisition) {
  const doc = existing || {
    schema_version: SCHEMA_VERSION,
    sha256: String(sha256),
    size_bytes: sizeBytes,
    acquisitions: [],
  };
  const seen = new Set(doc.acquisitions.map(identity));
  if (!seen.has(identity(acquisition))) doc.acquisitions.push(acquisition);
  return doc;
}

function write(samplesDir, doc) {
  const file = provenanceFile(samplesDir, doc.sha256);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`);
  return file;
}

// record is the whole operation: read, merge, write. Returns the file written.
function record(samplesDir, sha256, sizeBytes, acquisition) {
  return write(samplesDir, add(read(samplesDir, sha256), sha256, sizeBytes, acquisition));
}

/*
 * samplesDirFor locates the record's samples directory from any path beneath it. Callers
 * are holding a path to the stored sample, not to the record, and making each of them
 * reconstruct the record root is how they drift apart.
 */
function samplesDirFor(file) {
  let dir = path.dirname(path.resolve(file));
  while (dir !== path.dirname(dir)) {
    if (path.basename(dir) === "samples") return dir;
    dir = path.dirname(dir);
  }
  throw new Error(`not inside a samples directory: ${file}`);
}

/*
 * recordFor is the form an acquisition tool wants: hand it the stored file and the record
 * the collector wrote. The digest comes from the record rather than from the file, because
 * a sample held xz-compressed hashes to the container while provenance describes the
 * artifact that was fetched.
 */
function recordFor(storedFile, acquisition) {
  const artifact = acquisition.artifact || {};
  if (!artifact.sha256) throw new Error(`acquisition for ${storedFile} has no artifact.sha256`);
  return record(samplesDirFor(storedFile), artifact.sha256, artifact.size_bytes, acquisition);
}

module.exports = {
  SCHEMA_VERSION, provenanceFile, read, write, add, record, recordFor, identity, samplesDirFor,
};
