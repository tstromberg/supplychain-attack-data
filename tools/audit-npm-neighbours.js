#!/usr/bin/env node

/*
 * Which clean and remediated npm releases are still there for the taking.
 *
 * A differential corpus is only useful in pairs, and the corpus is lopsided: it holds the
 * compromised release far more often than the one before or after it. Those neighbours are
 * usually the easiest samples in the whole corpus to get, because an attacker's release is
 * unpublished while the maintainer's releases stay on the registry indefinitely.
 *
 * The distinction this has to get right is between a package that was compromised and
 * fixed, and a package the attacker created that npm then removed. The first has a real
 * remediated release; the second never will, and filing one would invent a state the
 * incident never had. The registry answers it directly -- a package whose packument is gone
 * has no neighbours, and one whose versions stop at the compromised release was never
 * fixed -- so nothing here is inferred from the record's prose.
 *
 * `before` is the published version immediately below the lowest affected one, `after` the
 * one immediately above the highest. Immediately, not merely nearby: a release two years
 * later differs from the compromised one in a thousand ways that have nothing to do with
 * the attack, and a detector told to find no difference between them is being asked the
 * wrong question.
 *
 *   node tools/audit-npm-neighbours.js [--out FILE] [--concurrency N]
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];
const COMPLETE = new Set(["exact", "probable_exact", "tree_equivalent", "checksum_verified",
  "source_snapshot"]);

/*
 * npm replaces a fully removed package with a `0.0.1-security` placeholder holding a
 * README and nothing else. It is a tombstone, not a remediated release: taking one as an
 * `after` would state that the maintainer fixed the package when in fact npm deleted it.
 */
const SECURITY_HOLDER = /-security$/;

function parseArgs(argv) {
  const options = { out: "", concurrency: 8 };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--out") options.out = argv[++i];
    else if (argv[i] === "--concurrency") options.concurrency = Number(argv[++i]) || 8;
    else if (argv[i] === "--help" || argv[i] === "-h") {
      process.stdout.write("Usage: node tools/audit-npm-neighbours.js [--out FILE] " +
        "[--concurrency N]\n");
      process.exit(0);
    }
  }
  return options;
}

/*
 * Semver-ish ordering. npm versions are semver by policy but the corpus also carries
 * prereleases and build suffixes, so numeric runs compare numerically, everything else
 * lexically, and a release with a prerelease tag sorts below the same release without one.
 */
function compareVersions(a, b) {
  const parse = v => {
    const [core, pre = ""] = String(v).split("-", 2);
    return [core.split(".").map(n => (/^\d+$/.test(n) ? Number(n) : n)), pre];
  };
  const [ax, apre] = parse(a);
  const [bx, bpre] = parse(b);
  for (let i = 0; i < Math.max(ax.length, bx.length); i += 1) {
    const p = ax[i];
    const q = bx[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    if (p !== q) return typeof p === "number" && typeof q === "number" ? p - q : (p < q ? -1 : 1);
  }
  if (apre === bpre) return 0;
  if (!apre) return 1;   // 1.0.0 is newer than 1.0.0-rc1
  if (!bpre) return -1;
  return apre < bpre ? -1 : 1;
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

// wanted groups the npm artifacts missing a before or an after, keyed by package.
function wanted() {
  const byPackage = new Map();
  for (const dir of records()) {
    const recordId = path.relative(ROOT, dir).split(path.sep).pop();
    const meta = yaml.load(fs.readFileSync(path.join(dir, "meta.yaml"), "utf8")) || [];
    const manifest = yaml.load(
      fs.readFileSync(path.join(dir, "samples", "manifest.yaml"), "utf8")) || {};

    const held = new Set();
    for (const sample of manifest.samples || []) {
      if (!COMPLETE.has(String((sample.verification || {}).status || ""))) continue;
      held.add(`${sample.artifact_id}/${sample.phase}`);
    }
    for (const item of meta) {
      for (const artifact of item.artifacts || []) {
        if (String(artifact.ecosystem || "").toLowerCase() !== "npm") continue;
        const hasBefore = held.has(`${artifact.id}/before`);
        const hasAfter = held.has(`${artifact.id}/after`);
        if (hasBefore && hasAfter) continue;
        const pkg = String(artifact.package || artifact.name || artifact.id);
        if (!byPackage.has(pkg)) byPackage.set(pkg, { pkg, affected: new Set(), artifacts: [] });
        const entry = byPackage.get(pkg);
        entry.artifacts.push({ dir, recordId, id: artifact.id, hasBefore, hasAfter });
        for (const version of artifact.versions || []) entry.affected.add(String(version));
      }
    }
  }
  return [...byPackage.values()];
}

async function packument(pkg) {
  const url = `https://registry.npmjs.org/${pkg.split("/").map(encodeURIComponent).join("/")}`;
  const response = await fetch(url, { headers: { accept: "application/json" } });
  if (response.status === 404) return { gone: true };
  if (!response.ok) return { error: `HTTP ${response.status}` };
  const body = await response.json();
  return { versions: Object.keys(body.versions || {}), time: body.time || {} };
}

async function main() {
  const options = parseArgs(process.argv);
  const targets = wanted();
  const results = [];
  let index = 0;

  async function worker() {
    while (index < targets.length) {
      const target = targets[index++];
      const published = await packument(target.pkg).catch(error => ({ error: error.message }));
      const affected = [...target.affected].sort(compareVersions);
      const row = { pkg: target.pkg, affected, artifacts: target.artifacts };

      if (published.gone) row.state = "unpublished";
      else if (published.error) row.state = `error: ${published.error}`;
      else {
        const live = published.versions.slice().sort(compareVersions);
        row.state = "published";
        if (affected.length) {
          const lowest = affected[0];
          const highest = affected[affected.length - 1];
          // The neighbours are the releases either side of the compromised span, not the
          // nearest release of any kind: an affected version still on the registry is not a
          // clean comparator for itself.
          row.before = live.filter(v => compareVersions(v, lowest) < 0 && !target.affected.has(v)).pop() || null;
          row.after = live.find(v => compareVersions(v, highest) > 0 && !target.affected.has(v) &&
            !SECURITY_HOLDER.test(v)) || null;
        } else {
          row.before = null;
          row.after = live.filter(v => !SECURITY_HOLDER.test(v)).pop() || null;
        }
      }
      results.push(row);
    }
  }
  await Promise.all(Array.from({ length: options.concurrency }, worker));

  const out = process.stdout;
  const state = kind => results.filter(row => row.state === kind);
  const needBefore = results.filter(row => row.artifacts.some(a => !a.hasBefore));
  const needAfter = results.filter(row => row.artifacts.some(a => !a.hasAfter));
  const gettableBefore = needBefore.filter(row => row.before);
  const gettableAfter = needAfter.filter(row => row.after);

  out.write(`${results.length} npm package(s) missing a clean or remediated neighbour\n`);
  out.write(`  still published on the registry: ${state("published").length}\n`);
  out.write(`  unpublished, no neighbour exists: ${state("unpublished").length}\n`);
  const errors = results.filter(row => String(row.state).startsWith("error"));
  if (errors.length) out.write(`  registry errors: ${errors.length}\n`);
  out.write(`\n  need before: ${needBefore.length}, of which a predecessor is published: ${gettableBefore.length}\n`);
  out.write(`  need after:  ${needAfter.length}, of which a successor is published:   ${gettableAfter.length}\n`);

  out.write(`\nsample of what is available:\n`);
  for (const row of gettableAfter.slice(0, 12)) {
    out.write(`  ${row.pkg}: affected ${row.affected.join(", ") || "(unstated)"} ` +
      `-> before ${row.before || "none"} / after ${row.after}\n`);
  }

  if (options.out) {
    fs.writeFileSync(options.out, JSON.stringify(results, (key, value) =>
      (key === "dir" ? undefined : value), 1));
    out.write(`\nwrote ${options.out}\n`);
  }
}

main().catch(error => {
  process.stderr.write(`audit-npm-neighbours: ${error.stack || error.message}\n`);
  process.exitCode = 1;
});
