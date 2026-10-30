#!/usr/bin/env node

/*
 * Give every sample an explicit subject: the thing that was compromised.
 *
 * The corpus names that thing two different ways. In most records `artifact_id` is the
 * package and `version` separates releases. In the AUR records one `artifact_id` stands
 * for hundreds of packages and `package` does the discriminating. A consumer cannot tell
 * which convention a record follows without inspecting it, so every consumer reimplements
 * the same guess -- and the generated artifact tree would have to guess too.
 *
 * The rule is chosen per artifact rather than per sample: an artifact whose samples name
 * more than one package is a stand-in for many subjects, so the package wins. Otherwise
 * the artifact id is the subject, which keeps the identifier the records already use.
 *
 * Subjects become directory names, so they must survive a filesystem and an object store.
 * This reports every name that would not, before anything is written.
 *
 *   node tools/normalize-subjects.js            report only
 *   node tools/normalize-subjects.js --apply    write `subject:` into the manifests
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];

// A subject is a single path segment. Anything that would nest it, escape it, or confuse
// an object store is reported rather than silently rewritten.
const UNSAFE = [
  [/\//, "contains a slash, which would nest the directory"],
  [/%/, "percent-encoded, which an object store may re-decode"],
  [/\s/, "contains whitespace"],
  [/[:\\<>"|?*]/, "contains a character a filesystem or object store reserves"],
  [/^\./, "starts with a dot, so it would be hidden"],
  [/^$/, "empty"],
];

function manifests() {
  const found = [];
  const walk = dir => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const child = path.join(dir, entry.name);
      if (entry.name === "refs") continue;
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
  const bySource = { artifact_id: 0, package: 0 };
  const unsafe = [];
  const collisions = [];
  let samples = 0;
  let changed = 0;
  const touched = [];

  for (const file of manifests()) {
    const record = path.relative(ROOT, path.dirname(path.dirname(file)));
    const manifest = yaml.load(fs.readFileSync(file, "utf8")) || {};
    const list = manifest.samples || [];
    if (!list.length) continue;

    // An artifact naming more than one package stands for many subjects.
    const packagesPerArtifact = new Map();
    for (const sample of list) {
      if (!sample.artifact_id) continue;
      if (!packagesPerArtifact.has(sample.artifact_id)) packagesPerArtifact.set(sample.artifact_id, new Set());
      if (sample.package) packagesPerArtifact.get(sample.artifact_id).add(String(sample.package));
    }

    const seen = new Map();
    let dirty = false;
    for (const sample of list) {
      samples += 1;
      const many = (packagesPerArtifact.get(sample.artifact_id) || new Set()).size > 1;
      const subject = String((many && sample.package) || sample.artifact_id || sample.package || "");
      bySource[many && sample.package ? "package" : "artifact_id"] += 1;

      for (const [pattern, why] of UNSAFE) {
        if (pattern.test(subject)) unsafe.push({ record, subject, why });
      }

      // Two subjects differing only by case collide on a case-insensitive filesystem.
      const fold = subject.toLowerCase();
      if (seen.has(fold) && seen.get(fold) !== subject) {
        collisions.push({ record, a: seen.get(fold), b: subject });
      }
      seen.set(fold, subject);

      if (sample.subject !== subject) {
        changed += 1;
        dirty = true;
        if (apply) sample.subject = subject;
      }
    }
    if (dirty && apply) {
      fs.writeFileSync(file, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
      touched.push(path.relative(ROOT, file));
    }
  }

  const out = process.stdout;
  out.write(`${samples} samples; ${changed} would gain or change a subject\n`);
  out.write(`  subject from artifact_id: ${bySource.artifact_id}\n`);
  out.write(`  subject from package:     ${bySource.package}\n`);

  const byReason = new Map();
  for (const item of unsafe) {
    if (!byReason.has(item.why)) byReason.set(item.why, []);
    byReason.get(item.why).push(item);
  }
  out.write(`\n${unsafe.length} sample(s) whose subject is not a safe path segment\n`);
  for (const [why, items] of byReason) {
    const names = [...new Set(items.map(i => i.subject))];
    out.write(`  ${items.length} ${why}\n`);
    out.write(`      ${names.slice(0, 4).join(", ")}${names.length > 4 ? `, +${names.length - 4} more` : ""}\n`);
  }

  out.write(`\n${collisions.length} case-insensitive collision(s)\n`);
  for (const c of collisions.slice(0, 6)) out.write(`  ${c.record}: ${c.a} vs ${c.b}\n`);

  if (apply) out.write(`\nwrote ${touched.length} manifest(s)\n`);
  else out.write(`\nreport only; pass --apply to write\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`normalize-subjects: ${error.message}\n`);
  process.exitCode = 1;
}
