#!/usr/bin/env node

/*
 * Retire the legacy `artifacts/` staging directories.
 *
 * Four records still carry an `artifacts/` tree beside `samples/`. It predates the
 * manifest: samples were curated there and copied across, and several manifest entries
 * still cite it as their source url. What stayed behind is invisible to everything --
 * `verify-oss-samples.js` does not see it, `build-artifacts.js` does not publish it, and
 * the ignore rules for the git/R2 split do not cover it, because it is not under
 * `samples/`. It would have been the last payload bytes left in the repository.
 *
 * Most of it is already held. A file counts as held when the corpus has its bytes either
 * as a sample in its own right or as a member of an archive a record holds -- an
 * extracted `.py` from a wheel that is itself a sample is a copy, not a second artifact.
 * Those are removed.
 *
 * What is left is reported, not adopted. Each one needs a classification, a phase and a
 * note that says what it is, and a tool that guessed those would be inventing evidence.
 * They are listed so they can be entered deliberately.
 *
 *   node tools/adopt-artifacts.js            report only
 *   node tools/adopt-artifacts.js --apply    remove what the corpus already holds
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

// Editor and filesystem droppings. Never evidence, whatever directory they turn up in.
const JUNK = new Set([".DS_Store", "Thumbs.db", ".localized"]);

const sha256 = buffer => crypto.createHash("sha256").update(buffer).digest("hex");

function walkFiles(dir, found = []) {
  if (!fs.existsSync(dir)) return found;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walkFiles(file, found);
    else found.push(file);
  }
  return found;
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

/*
 * archiveKind sniffs the container from its first bytes. Extensions are not usable here:
 * a third of the corpus is stored under names a provider invented, so the malicious
 * ultralytics releases are `.sample` files that happen to be zips, and choosing an
 * unpacker by suffix silently skips them.
 */
function archiveKind(file) {
  const handle = fs.openSync(file, "r");
  const head = Buffer.alloc(6);
  try {
    fs.readSync(handle, head, 0, 6, 0);
  } finally {
    fs.closeSync(handle);
  }
  if (head[0] === 0x50 && head[1] === 0x4b) return "zip";
  if (head[0] === 0x1f && head[1] === 0x8b) return "tar";
  if (head[0] === 0x42 && head[1] === 0x5a) return "tar";
  if (head.toString("hex").startsWith("fd377a585a")) return "xz";
  return null;
}

/*
 * memberDigests unpacks an archive and hashes what comes out. Shelling out to the system
 * unpackers keeps this dependency-free; an archive neither can read contributes nothing,
 * which only ever means a file is reported rather than removed.
 */
function memberDigests(archive) {
  const digests = new Set();
  const kind = archiveKind(archive);
  if (!kind || kind === "xz") return digests;
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "adopt-"));
  try {
    if (kind === "zip") execFileSync("unzip", ["-qq", "-o", archive, "-d", temp], { stdio: "ignore" });
    else execFileSync("tar", ["xf", archive, "-C", temp], { stdio: "ignore" });
    for (const file of walkFiles(temp)) digests.add(sha256(fs.readFileSync(file)));
  } catch {
    return digests;
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
  return digests;
}

/*
 * digestsOf gives every digest a staged file can legitimately match. A container the
 * staging tree compressed is still the same artifact: the two kong binaries are held
 * decompressed as samples and staged as .xz, and comparing containers would call them new.
 */
function digestsOf(file, body) {
  const digests = [sha256(body)];
  if (archiveKind(file) === "xz") {
    try {
      digests.push(sha256(execFileSync("xz", ["-dc", file], { maxBuffer: 1024 * 1024 * 1024 })));
    } catch { /* an unreadable container is simply not matched */ }
  }
  return digests;
}

function main() {
  const apply = process.argv.includes("--apply");
  const held = [];
  const unregistered = [];
  const junk = [];
  let bytes = 0;

  // Every digest the corpus claims, so a copy staged under one record is recognised even
  // when the sample that supersedes it lives under another.
  const sampleDigests = new Map();
  for (const dir of records()) {
    const manifest = yaml.load(
      fs.readFileSync(path.join(dir, "samples", "manifest.yaml"), "utf8")) || {};
    for (const sample of manifest.samples || []) {
      if (sample.sha256) {
        sampleDigests.set(String(sample.sha256),
          `${sample.subject || sample.artifact_id}/${sample.phase}/${sample.filename}`);
      }
    }
  }

  for (const dir of records()) {
    const staging = path.join(dir, "artifacts");
    if (!fs.existsSync(staging)) continue;
    const relative = path.relative(ROOT, dir);

    // Members are only unpacked for records that actually have a staging tree.
    const members = new Map();
    for (const file of walkFiles(path.join(dir, "samples"))) {
      if (file.endsWith("manifest.yaml") || file.includes(`${path.sep}provenance${path.sep}`)) continue;
      for (const digest of memberDigests(file)) {
        if (!members.has(digest)) members.set(digest, path.relative(path.join(dir, "samples"), file));
      }
    }

    for (const file of walkFiles(staging)) {
      const name = path.basename(file);
      const body = fs.readFileSync(file);
      const candidates = digestsOf(file, body);
      const where = path.relative(ROOT, file);
      const asSample = candidates.find(d => sampleDigests.has(d));
      const asMember = candidates.find(d => members.has(d));

      if (JUNK.has(name)) {
        junk.push(where);
        bytes += body.length;
      } else if (asSample) {
        held.push(`${where}  == sample ${sampleDigests.get(asSample)}`);
        bytes += body.length;
      } else if (asMember) {
        held.push(`${where}  == member of ${members.get(asMember)}`);
        bytes += body.length;
      } else {
        unregistered.push({ record: relative, file: where, size: body.length, sha256: candidates[0] });
      }
    }
  }

  if (apply) {
    for (const line of [...held, ...junk]) {
      const file = path.join(ROOT, line.split("  ==")[0]);
      if (fs.existsSync(file)) {
        fs.chmodSync(file, 0o644);
        fs.rmSync(file);
      }
    }
    // A staging tree that is now empty should not survive as a suggestion that it is used.
    for (const dir of records()) {
      const staging = path.join(dir, "artifacts");
      if (fs.existsSync(staging) && walkFiles(staging).length === 0) {
        fs.rmSync(staging, { recursive: true });
      }
    }
  }

  const out = process.stdout;
  out.write(`${held.length + junk.length + unregistered.length} file(s) under artifacts/\n`);
  out.write(`  already held by the corpus: ${held.length}\n`);
  out.write(`  editor droppings:           ${junk.length}\n`);
  out.write(`  not held anywhere:          ${unregistered.length}\n`);
  out.write(`  removable:                  ${(bytes / 1048576).toFixed(1)} MB\n`);

  const byReason = new Map();
  for (const line of held) {
    const kind = line.includes("== member of") ? "member of a held archive" : "copy of a sample";
    byReason.set(kind, (byReason.get(kind) || 0) + 1);
  }
  for (const [kind, n] of byReason) out.write(`      ${n} ${kind}\n`);

  if (unregistered.length) {
    out.write(`\nnot held anywhere -- enter these deliberately or delete them:\n`);
    for (const item of unregistered) {
      out.write(`  ${item.file}\n      ${item.size} bytes  sha256 ${item.sha256}\n`);
    }
  }
  out.write(apply ? `\nremoved what the corpus already holds\n` : `\nreport only; pass --apply to remove\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`adopt-artifacts: ${error.stack || error.message}\n`);
  process.exitCode = 1;
}
