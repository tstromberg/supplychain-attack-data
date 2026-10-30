#!/usr/bin/env node

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");
const { TERMS } = require("./normalize-basis.js");
const provenance = require("./provenance-store.js");

const root = path.resolve(__dirname, "..");
const sampleRoots = [path.join(root, "oss", "attacks"), path.join(root, "proprietary")];
const errors = [];
// Samples filed under an artifact id no meta.yaml declares. These are real recovered
// bytes, but tools/missing-samples.js counts coverage against the artifacts a record
// names, so nothing filed this way is ever counted. Reported rather than failed: some
// ids are deliberate evidence holders, and declaring them is a record-structure
// decision rather than a repair.
const undeclared = [];
let manifests = 0;
let samples = 0;
let reconstructions = 0;

function walk(dir, name, found = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(file, name, found);
    else if (entry.name === name) found.push(file);
  }
  return found;
}

function digest(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

async function main() {
for (const sampleRoot of sampleRoots) for (const manifestFile of walk(sampleRoot, "manifest.yaml")) {
  if (path.basename(path.dirname(manifestFile)) !== "samples") continue;
  manifests += 1;
  const sampleRoot = path.dirname(manifestFile);
  const manifest = yaml.load(fs.readFileSync(manifestFile, "utf8")) || {};
  const referenced = new Set();
  const metaFile = path.join(path.dirname(sampleRoot), "meta.yaml");
  let declared = null;
  if (fs.existsSync(metaFile)) {
    try {
      const doc = yaml.load(fs.readFileSync(metaFile, "utf8")) || [];
      declared = new Set(doc.flatMap(entry => (entry.artifacts || []).map(a => a.id)));
    } catch {
      declared = null;
    }
  }
  for (const sample of manifest.samples || []) {
    samples += 1;
    const file = path.resolve(sampleRoot, sample.path || "");
    if (file !== sampleRoot && !file.startsWith(`${sampleRoot}${path.sep}`)) {
      errors.push(`${manifestFile}: path escapes samples directory: ${sample.path}`);
      continue;
    }
    referenced.add(file);
    if (declared && sample.artifact_id && !declared.has(sample.artifact_id)) {
      undeclared.push(`${manifestFile}: ${sample.artifact_id} is not declared in meta.yaml, ` +
        `so this sample is not counted as coverage`);
    }
    // A `during` sample is the artifact as the attack left it. A clean file filed there
    // is not that, and it would be counted as coverage, reporting an artifact as covered
    // when the malicious bytes were never obtained. Clean bytes belong in `before` or
    // `after`. tools/rephase-clean-during.js moves an existing one.
    if (sample.phase === "during" && (String(sample.classification || "") === "clean" ||
        String(sample.source?.kind || "") === "clean_comparator_distribution")) {
      errors.push(`${manifestFile}: ${sample.filename} is clean but filed under during; ` +
        `a clean sample belongs in before or after`);
    }
    /*
     * `basis` is a controlled vocabulary: it is the corpus's only groupable statement of
     * why the bytes are believed to be what the record claims, and it stops being one the
     * moment a free-text value is admitted. It had drifted to 1,413 distinct values, 937
     * of them used once. Particulars belong in `evidence`, which is deliberately free.
     */
    for (const value of (sample.verification || {}).basis || []) {
      if (!TERMS.has(String(value))) {
        errors.push(`${manifestFile}: ${sample.filename} has basis "${value}", which is not ` +
          `in the vocabulary; put the particulars in verification.evidence instead ` +
          `(tools/normalize-basis.js lists the terms)`);
      }
    }

    /*
     * Samples are held as the bytes that were distributed. The xz containers that used to
     * sit between the manifest and the file existed only to fit git's 100 MiB ceiling,
     * which stopped applying when payloads moved to the artifact tree; a `storage` block
     * now means a tool is reintroducing a representation nothing else understands.
     */
    if (sample.storage) {
      errors.push(`${file}: carries a storage container; samples are stored uncompressed ` +
        `(tools/decompress-samples.js removes one)`);
      continue;
    }
    if (!fs.existsSync(file)) {
      errors.push(`${manifestFile}: missing ${sample.path}`);
      continue;
    }
    const stat = fs.statSync(file);
    const measured = digest(file);
    const measuredSize = stat.size;
    if (measured !== sample.sha256) errors.push(`${file}: sha256 ${measured} != ${sample.sha256}`);
    if (measuredSize !== sample.size) errors.push(`${file}: size ${measuredSize} != ${sample.size}`);
    // A reconstruction was built here, not fetched, so it has no capture sidecar. Its
    // provenance is the reconstruction record, and it must never claim original bytes.
    const rebuilt = (sample.source || {}).reconstruction;
    if (rebuilt) {
      const status = (sample.verification || {}).status;
      if (!["tree_equivalent", "payload_only"].includes(status)) {
        errors.push(`${file}: reconstruction must be tree_equivalent or payload_only, not ${status}`);
      }
      if (!rebuilt.method) errors.push(`${file}: reconstruction is missing method`);
      // A reconstruction record names its inputs under several keys (base, derived,
      // replaced). Check every path/sha256 pair it declares, whatever it is called.
      const inputs = [];
      const collect = node => {
        if (!node || typeof node !== "object") return;
        if (Array.isArray(node)) { node.forEach(collect); return; }
        if (typeof node.path === "string" && typeof node.sha256 === "string") inputs.push(node);
        Object.values(node).forEach(collect);
      };
      collect(rebuilt);
      for (const input of inputs) {
        const inputFile = path.resolve(sampleRoot, input.path);
        if (!fs.existsSync(inputFile)) continue;
        const measured = digest(inputFile);
        if (measured !== input.sha256) {
          errors.push(`${file}: reconstruction input ${input.path} sha256 ${measured} != ${input.sha256}`);
        }
      }
      reconstructions += 1;
      const rebuiltSidecar = provenance.provenanceFile(sampleRoot, sample.sha256);
      if (!fs.existsSync(rebuiltSidecar)) {
        errors.push(`${file}: reconstruction is missing its provenance record`);
      } else {
        try {
          const doc = JSON.parse(fs.readFileSync(rebuiltSidecar, "utf8"));
          // Any one acquisition may carry the chain; it only has to be recorded once.
          const chained = (doc.acquisitions || []).some(a => a.provenance || a.reconstruction);
          if (!chained) {
            errors.push(`${rebuiltSidecar}: no acquisition repeats the reconstruction chain`);
          }
          if (doc.sha256 !== sample.sha256) errors.push(`${rebuiltSidecar}: sha256 mismatch`);
        } catch (error) {
          errors.push(`${rebuiltSidecar}: invalid JSON: ${error.message}`);
        }
      }
      const rebuiltPartial = `${file}.partial.json`;
      if (fs.existsSync(rebuiltPartial)) {
        referenced.add(rebuiltPartial);
        if (sample.verification?.status !== "payload_only") {
          errors.push(`${file}: partial capture must use verification.status payload_only`);
        }
        try {
          const partial = JSON.parse(fs.readFileSync(rebuiltPartial, "utf8"));
          if (!Array.isArray(partial.missing) || partial.missing.length === 0) {
            errors.push(`${rebuiltPartial}: partial record lists no missing members`);
          }
        } catch (error) {
          errors.push(`${rebuiltPartial}: invalid JSON: ${error.message}`);
        }
      }
      continue;
    }

    // Provenance is keyed on the digest, so it does not move when a sample is re-phased.
    const sidecarFile = provenance.provenanceFile(sampleRoot, sample.sha256);
    if (!fs.existsSync(sidecarFile)) {
      errors.push(`${file}: no provenance record for ${String(sample.sha256).slice(0, 12)}`);
      continue;
    }
    const visiblyReconstructed = /(?:^|-)RECONSTRUCTED\./.test(path.basename(file));
    if (visiblyReconstructed) {
      const reconstruction = sample.source?.reconstruction;
      if (sample.source?.kind !== "reconstructed_distribution") {
        errors.push(`${file}: RECONSTRUCTED artifact must use source.kind reconstructed_distribution`);
      }
      if (sample.verification?.status !== "tree_equivalent") {
        errors.push(`${file}: RECONSTRUCTED artifact must use verification.status tree_equivalent`);
      }
      if (reconstruction?.method === "forager_file_tree_assembly") {
        if (!reconstruction?.retained_tree?.url || !reconstruction?.retained_tree?.kind ||
            !reconstruction?.retained_tree?.verification) {
          errors.push(`${file}: direct-tree reconstruction is missing retained-tree provenance`);
        }
      } else {
        if (!reconstruction?.base?.path || !reconstruction?.base?.sha256 ||
            !Number.isInteger(reconstruction?.base?.member_count)) {
          errors.push(`${file}: reconstruction is missing its base path, digest, or member count`);
        }
        if (!reconstruction?.retained_manifest?.url || !reconstruction?.retained_manifest?.sha256 ||
            !Number.isInteger(reconstruction?.retained_manifest?.member_count) ||
            !reconstruction?.retained_manifest?.member_hash) {
          errors.push(`${file}: reconstruction is missing retained-manifest provenance`);
        }
        if (!Array.isArray(reconstruction?.overlays) || !reconstruction.overlays.length ||
            reconstruction.overlays.some(item => !item.path || !item.operation || !item.sha256)) {
          errors.push(`${file}: reconstruction must document every overlay path, operation, and digest`);
        }
        if (!Number.isInteger(reconstruction?.unchanged_members?.count) ||
            !reconstruction?.unchanged_members?.verification) {
          errors.push(`${file}: reconstruction is missing unchanged-member accounting`);
        }
      }
      if (!reconstruction?.packaging?.format || !reconstruction?.packaging?.path_order ||
          reconstruction?.packaging?.original_archive_bytes_recovered !== false) {
        errors.push(`${file}: reconstruction is missing synthetic packaging details`);
      }
    }
    /*
     * The document is checked against the bytes, and each acquisition against the shape a
     * collector is expected to write. The filename is deliberately not checked: it is a
     * property of where the corpus filed the artifact, not of the bytes, and the same
     * bytes are routinely acquired under several names -- one AUR .desktop file arrives
     * from nine different commits.
     */
    try {
      const doc = JSON.parse(fs.readFileSync(sidecarFile, "utf8"));
      if (doc.sha256 !== measured) errors.push(`${sidecarFile}: sha256 ${doc.sha256} != ${measured}`);
      if (doc.size_bytes !== measuredSize) errors.push(`${sidecarFile}: size mismatch`);
      const acquisitions = doc.acquisitions || [];
      if (!acquisitions.length) errors.push(`${sidecarFile}: records no acquisition`);
      for (const [index, acquisition] of acquisitions.entries()) {
        if (!acquisition.fetch?.url) errors.push(`${sidecarFile}: acquisition ${index} has no fetch.url`);
        if (!acquisition.fetch?.at) errors.push(`${sidecarFile}: acquisition ${index} has no fetch.at`);
      }
      if (visiblyReconstructed && !acquisitions.some(a => a.provenance?.reconstruction)) {
        errors.push(`${sidecarFile}: RECONSTRUCTED artifact records no reconstruction chain`);
      }
    } catch (error) {
      errors.push(`${sidecarFile}: invalid JSON: ${error.message}`);
    }

    // A partial reconstruction is missing archive members, so it must never be
    // presented as the published package. Its accounting record travels with it.
    const partialFile = `${file}.partial.json`;
    if (fs.existsSync(partialFile)) {
      referenced.add(partialFile);
      if (sample.verification?.status !== "payload_only") {
        errors.push(`${file}: partial capture must use verification.status payload_only`);
      }
      try {
        const partial = JSON.parse(fs.readFileSync(partialFile, "utf8"));
        if (!Array.isArray(partial.missing) || partial.missing.length === 0) {
          errors.push(`${partialFile}: partial record lists no missing members`);
        }
      } catch (error) {
        errors.push(`${partialFile}: invalid JSON: ${error.message}`);
      }
    } else if (sample.verification?.status === "payload_only" && /-partial\./.test(path.basename(file))) {
      errors.push(`${file}: partial capture is missing its .partial.json record`);
    }
  }
  // Enumerate ordinary files separately: every payload must be represented in
  // the manifest, while manifest.yaml and provenance sidecars are metadata.
  const stack = [sampleRoot];
  while (stack.length) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (path.relative(sampleRoot, file) !== "provenance") stack.push(file);
      } else if (file !== manifestFile && entry.name !== ".gitignore" &&
        !entry.name.endsWith(".forage.json") && !referenced.has(file)) {
        errors.push(`${file}: payload is not listed in manifest`);
      }
    }
  }
}

}

main().then(() => {
if (errors.length) {
  process.stderr.write(`${errors.join("\n")}\n`);
  process.stderr.write(`FAILED: ${errors.length} error(s) across ${samples} samples in ${manifests} manifests\n`);
  process.exitCode = 1;
} else {
  const parts = [];
  if (reconstructions) parts.push(`${reconstructions} reconstructed from recovered sources`);
  const note = parts.length ? `; ${parts.join("; ")}` : "";
  process.stdout.write(`OK: ${samples} samples in ${manifests} manifests; hashes, sizes, paths, and provenance records verified${note}\n`);
  if (undeclared.length) {
    const records = new Set(undeclared.map(line => line.split(":")[0]));
    process.stdout.write(`\nNOTICE: ${undeclared.length} sample(s) in ${records.size} record(s) are filed ` +
      `under an artifact id meta.yaml does not declare, so they count as no coverage:\n`);
    for (const line of undeclared) process.stdout.write(`  ${line}\n`);
  }
}
}).catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
