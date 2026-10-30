#!/usr/bin/env node

/*
 * Undo the xz storage containers. Samples are held as the bytes that were distributed.
 *
 * A sample's identity has always been the artifact's own SHA-256 and size. The container
 * was never part of that; it existed for one reason, which is that GitHub rejects a blob
 * over 100 MiB and git handles large binaries poorly. Compressing bought very little even
 * then -- these are installers and archives, already compressed, so xz took 1,912 MB down
 * to 1,738 MB, about 9% -- and for eight samples it bought nothing at all: still over the
 * limit, so they were excluded from the repository with a .gitignore beside them.
 *
 * Once payload bytes live in the artifact tree rather than in git, the ceiling that
 * justified all of it no longer applies to them, and what is left is a second
 * representation that every consumer has to know about. The artifact tree already
 * decompresses on the way out, so this changes nothing a researcher sees; it removes a
 * case from the middle of the pipeline.
 *
 * The digest is checked against the manifest before the container is removed. A
 * decompressed file that does not reproduce the recorded artifact digest is left alone
 * and reported, because that would mean the manifest and the bytes disagree.
 *
 *   node tools/decompress-samples.js            report only
 *   node tools/decompress-samples.js --apply    decompress and drop the storage block
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];

// The header excludeFromGit() wrote. AUR packages ship their own .gitignore as a sample,
// so an exclusion file is recognised by what it says, never by its name.
const EXCLUSION_MARKER = "GitHub rejects any single file over 100 MiB";

function manifests() {
  const found = [];
  const walk = dir => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name === "refs") continue;
      const child = path.join(dir, entry.name);
      if (entry.name === "samples") {
        const file = path.join(child, "manifest.yaml");
        if (fs.existsSync(file)) found.push(file);
        continue;
      }
      walk(child);
    }
  };
  for (const scope of SCOPES) walk(scope);
  return found;
}

function main() {
  const apply = process.argv.includes("--apply");
  let converted = 0;
  let absent = 0;
  let reclaimed = 0;
  const mismatched = [];
  const exclusions = new Set();
  const touched = [];

  for (const file of manifests()) {
    const samplesDir = path.dirname(file);
    const manifest = yaml.load(fs.readFileSync(file, "utf8")) || {};
    let dirty = false;

    for (const sample of manifest.samples || []) {
      if (!sample.storage) continue;
      if (String(sample.storage.format) !== "xz") {
        mismatched.push(`${sample.path}: unsupported container ${sample.storage.format}`);
        continue;
      }
      const stored = path.join(samplesDir, String(sample.path));
      if (!fs.existsSync(stored)) {
        absent += 1;
        continue;
      }

      const body = execFileSync("xz", ["-dc", stored], { maxBuffer: 1024 * 1024 * 1024 });
      const digest = crypto.createHash("sha256").update(body).digest("hex");
      if (digest !== sample.sha256 || body.length !== sample.size) {
        mismatched.push(`${sample.path}: decompresses to ${digest.slice(0, 12)}/${body.length}, ` +
          `manifest says ${String(sample.sha256).slice(0, 12)}/${sample.size}`);
        continue;
      }

      const plain = stored.replace(/\.xz$/, "");
      converted += 1;
      reclaimed += fs.statSync(stored).size;

      // The .gitignore beside an excluded sample described a constraint that no longer
      // applies. It is rewritten without that line, and removed when nothing else is in it.
      const exclusion = path.join(path.dirname(stored), ".gitignore");
      if (fs.existsSync(exclusion) && fs.readFileSync(exclusion, "utf8").includes(EXCLUSION_MARKER)) {
        exclusions.add(exclusion);
      }

      if (apply) {
        fs.writeFileSync(plain, body);
        fs.chmodSync(plain, 0o444);
        fs.chmodSync(stored, 0o644);
        fs.rmSync(stored);
        sample.path = path.relative(samplesDir, plain);
        delete sample.storage;
        dirty = true;
      }
    }

    if (dirty && apply) {
      fs.writeFileSync(file, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
      touched.push(path.relative(ROOT, file));
    }
  }

  if (apply) {
    for (const exclusion of exclusions) {
      const kept = fs.readFileSync(exclusion, "utf8")
        .split("\n")
        .filter(line => !line.startsWith("#") && line.trim() && !line.trim().endsWith(".xz"));
      if (kept.length) fs.writeFileSync(exclusion, `${kept.join("\n")}\n`);
      else fs.rmSync(exclusion);
    }
  }

  const out = process.stdout;
  out.write(`${converted} sample(s) decompressed, ${(reclaimed / 1048576).toFixed(0)} MB of ` +
    `container reclaimed\n`);
  out.write(`  exclusion .gitignore files cleared: ${exclusions.size}\n`);
  out.write(`  containers absent from disk:        ${absent}\n`);
  out.write(`  refused (bytes disagree):           ${mismatched.length}\n`);
  for (const item of mismatched.slice(0, 10)) out.write(`      ${item}\n`);
  out.write(apply ? `\nwrote ${touched.length} manifest(s)\n` : `\nreport only; pass --apply to write\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`decompress-samples: ${error.stack || error.message}\n`);
  process.exitCode = 1;
}
