"use strict";

/*
 * Storage form for acquired samples.
 *
 * A sample's identity is the artifact's own bytes: its SHA-256 and size are what
 * reported hashes, provenance sidecars, and incident records are stated in. How the
 * repository stores those bytes is a separate concern. Large samples are kept
 * xz-compressed, and the manifest records the container alongside the artifact so the
 * identity never changes when the storage form does.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

// Git handles large binaries poorly and GitHub rejects any single file over 100 MiB,
// so samples are compressed well before that ceiling rather than at it.
const COMPRESS_THRESHOLD_BYTES = 75 * 1024 * 1024;

// GitHub's hard per-file limit. A push containing a larger blob is refused outright,
// so a sample still above this after compression cannot live in the repository.
const GIT_MAX_BYTES = 100 * 1024 * 1024;

const GITIGNORE_HEADER = `# GitHub rejects any single file over 100 MiB. These samples are already-compressed
# installers, so xz leaves them above the limit and no setting brings them under it.
# The bytes stay local and are excluded from the repository. Their manifest entries
# record storage.committed: false, keeping the artifact's identity and provenance
# sidecar in git so the sample can be re-acquired or restored from another store.
# See "Storage form" in SAMPLE_ACQUISITION.md.
`;

/*
 * excludeFromGit adds file's basename to the .gitignore beside it, creating the file
 * with an explanation when absent. Keeping the rule next to the sample means a reader
 * who finds the gap sees why it is there.
 */
function excludeFromGit(file) {
  const dir = path.dirname(file);
  const name = path.basename(file);
  const ignoreFile = path.join(dir, ".gitignore");
  const existing = fs.existsSync(ignoreFile) ? fs.readFileSync(ignoreFile, "utf8") : GITIGNORE_HEADER;
  if (existing.split("\n").some(line => line.trim() === name)) return;
  fs.writeFileSync(ignoreFile, `${existing.replace(/\n*$/, "\n")}${name}\n`);
}

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

// storageFor describes a stored file for the manifest. It returns null when the file
// is stored as-is, so an ordinary sample keeps its existing shape.
function storageFor(storedPath, format) {
  if (!format) return null;
  const size = fs.statSync(storedPath).size;
  const storage = { format, sha256: sha256File(storedPath), size };
  // A sample git cannot carry is excluded rather than left to break every push.
  if (size > GIT_MAX_BYTES) {
    storage.committed = false;
    excludeFromGit(storedPath);
  }
  return storage;
}

/*
 * compressLargeSample xz-compresses file when it exceeds the threshold, replacing it
 * with "<file>.xz". The provenance sidecar keeps the artifact's own name, because it
 * describes the artifact and not the container.
 *
 * Returns { path, storage }: the path now on disk, and the container description, or
 * a null storage when the file was small enough to keep verbatim.
 */
function compressLargeSample(file) {
  const size = fs.statSync(file).size;
  if (size <= COMPRESS_THRESHOLD_BYTES) return { path: file, storage: null };

  // -T0 uses every core; the default preset is a good trade for installer-sized
  // inputs, most of which are already compressed and barely shrink.
  const result = spawnSync("xz", ["-T0", "-q", "-f", file], { stdio: ["ignore", "ignore", "pipe"] });
  if (result.error || result.status !== 0) {
    const detail = result.error?.message || String(result.stderr || "").trim() || `exit ${result.status}`;
    process.stderr.write(`warning: leaving ${file} uncompressed: ${detail}\n`);
    return { path: file, storage: null };
  }

  const compressed = `${file}.xz`;
  return { path: compressed, storage: storageFor(compressed, "xz") };
}

/*
 * measureStored returns the artifact's own sha256 and size from a stored file,
 * decompressing on the fly when the manifest says the file is a container. Nothing is
 * written to disk and the archive is never opened as an archive, only hashed.
 */
function measureStored(file, storage) {
  if (!storage || storage.format !== "xz") {
    return Promise.resolve({ sha256: sha256File(file), size: fs.statSync(file).size });
  }
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    let size = 0;
    const child = spawn("xz", ["-dc", file], { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stdout.on("data", chunk => {
      hash.update(chunk);
      size += chunk.length;
    });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", code => {
      if (code !== 0) return reject(new Error(stderr.trim() || `xz exited ${code}`));
      resolve({ sha256: hash.digest("hex"), size });
    });
  });
}

// artifactPath strips the storage container from a stored path, giving the artifact's
// own filename — the name its provenance sidecar is keyed on.
function artifactPath(storedPath, storage) {
  if (storage?.format === "xz" && storedPath.endsWith(".xz")) return storedPath.slice(0, -3);
  return storedPath;
}

module.exports = {
  COMPRESS_THRESHOLD_BYTES,
  GIT_MAX_BYTES,
  excludeFromGit,
  compressLargeSample,
  measureStored,
  artifactPath,
  sha256File,
  storageFor,
};
