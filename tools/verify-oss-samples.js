#!/usr/bin/env node

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");
const { measureStored, artifactPath } = require("./sample-storage.js");

const root = path.resolve(__dirname, "..");
const sampleRoots = [path.join(root, "oss", "attacks"), path.join(root, "proprietary")];
const errors = [];
let manifests = 0;
let samples = 0;
let uncommitted = 0;
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
  for (const sample of manifest.samples || []) {
    samples += 1;
    const file = path.resolve(sampleRoot, sample.path || "");
    if (file !== sampleRoot && !file.startsWith(`${sampleRoot}${path.sep}`)) {
      errors.push(`${manifestFile}: path escapes samples directory: ${sample.path}`);
      continue;
    }
    referenced.add(file);
    // A sample too large for git is excluded from the repository by a .gitignore
    // beside it. Its absence in a fresh clone is the recorded state, not a fault;
    // when the bytes are present locally they are still verified in full.
    const notCommitted = sample.storage?.committed === false;
    if (!fs.existsSync(file)) {
      if (notCommitted) {
        uncommitted += 1;
        continue;
      }
      errors.push(`${manifestFile}: missing ${sample.path}`);
      continue;
    }
    if (notCommitted) uncommitted += 1;
    const stat = fs.statSync(file);
    // A sample's sha256 and size always describe the artifact itself. When the
    // repository stores it compressed, the container is checked separately and the
    // artifact's own bytes are measured by streaming the decompressed form.
    const storage = sample.storage || null;
    if (storage) {
      if (storage.format !== "xz") {
        errors.push(`${file}: unsupported storage format ${storage.format}`);
        continue;
      }
      const storedDigest = digest(file);
      if (storedDigest !== storage.sha256) errors.push(`${file}: stored sha256 ${storedDigest} != ${storage.sha256}`);
      if (stat.size !== storage.size) errors.push(`${file}: stored size ${stat.size} != ${storage.size}`);
    }
    let measured;
    let measuredSize;
    try {
      ({ sha256: measured, size: measuredSize } = await measureStored(file, storage));
    } catch (error) {
      errors.push(`${file}: cannot read stored sample: ${error.message}`);
      continue;
    }
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
      const rebuiltSidecar = `${artifactPath(file, storage)}.forage.json`;
      if (!fs.existsSync(rebuiltSidecar)) {
        errors.push(`${file}: reconstruction is missing its provenance sidecar`);
      } else {
        try {
          const sc = JSON.parse(fs.readFileSync(rebuiltSidecar, "utf8"));
          if (!sc.provenance && !sc.reconstruction) {
            errors.push(`${rebuiltSidecar}: sidecar does not repeat the reconstruction chain`);
          }
          if (sc.artifact?.sha256 !== measured) errors.push(`${rebuiltSidecar}: artifact sha256 mismatch`);
        } catch (error) {
          errors.push(`${rebuiltSidecar}: invalid JSON: ${error.message}`);
        }
      }
      continue;
    }

    // The sidecar is named for the artifact, not for the container it is stored in.
    const sidecarFile = `${artifactPath(file, storage)}.forage.json`;
    if (!fs.existsSync(sidecarFile)) {
      errors.push(`${file}: missing provenance sidecar`);
      continue;
    }
    const visiblyReconstructed = /(?:^|-)RECONSTRUCTED\./.test(path.basename(artifactPath(file, storage)));
    if (visiblyReconstructed) {
      const reconstruction = sample.source?.reconstruction;
      if (sample.source?.kind !== "reconstructed_distribution") {
        errors.push(`${file}: RECONSTRUCTED artifact must use source.kind reconstructed_distribution`);
      }
      if (sample.verification?.status !== "tree_equivalent") {
        errors.push(`${file}: RECONSTRUCTED artifact must use verification.status tree_equivalent`);
      }
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
      if (!reconstruction?.packaging?.format || !reconstruction?.packaging?.path_order ||
          reconstruction?.packaging?.original_archive_bytes_recovered !== false) {
        errors.push(`${file}: reconstruction is missing synthetic packaging details`);
      }
    }
    try {
      const sidecar = JSON.parse(fs.readFileSync(sidecarFile, "utf8"));
      if (sidecar.artifact?.sha256 !== measured) errors.push(`${sidecarFile}: artifact sha256 mismatch`);
      if (sidecar.artifact?.size_bytes !== measuredSize) errors.push(`${sidecarFile}: artifact size mismatch`);
      if (sidecar.artifact?.filename !== path.basename(artifactPath(file, storage))) errors.push(`${sidecarFile}: artifact filename mismatch`);
      if (!sidecar.fetch?.url) errors.push(`${sidecarFile}: missing fetch.url`);
      if (!sidecar.fetch?.at) errors.push(`${sidecarFile}: missing fetch.at`);
      if (visiblyReconstructed && !sidecar.provenance?.reconstruction) {
        errors.push(`${sidecarFile}: RECONSTRUCTED artifact is missing its sidecar reconstruction chain`);
      }
    } catch (error) {
      errors.push(`${sidecarFile}: invalid JSON: ${error.message}`);
    }

    // A partial reconstruction is missing archive members, so it must never be
    // presented as the published package. Its accounting record travels with it.
    const partialFile = `${artifactPath(file, storage)}.partial.json`;
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
      if (entry.isDirectory()) stack.push(file);
      else if (file !== manifestFile && entry.name !== ".gitignore" &&
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
  if (uncommitted) parts.push(`${uncommitted} too large for git and excluded from the repository`);
  if (reconstructions) parts.push(`${reconstructions} reconstructed from recovered sources`);
  const note = parts.length ? `; ${parts.join("; ")}` : "";
  process.stdout.write(`OK: ${samples} samples in ${manifests} manifests; hashes, sizes, paths, and provenance sidecars verified${note}\n`);
}
}).catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
