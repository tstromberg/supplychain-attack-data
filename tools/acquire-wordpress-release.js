#!/usr/bin/env node

/*
 * Collects the WordPress.org release either side of a compromised one.
 *
 * WordPress.org keeps every version a theme or plugin has published, including for
 * projects that were later closed, so the release that ended an incident is normally
 * still served from the registry that served the bad one. That makes an `after` sample
 * one of the few things in this corpus that is reliably obtainable.
 *
 * The download URL is not the evidence. downloads.wordpress.org will answer for a
 * coordinate that does not exist, so what is checked is the archive's own metadata: a
 * theme declares its version in style.css and a plugin in its readme or main PHP file,
 * and an archive that does not declare the fixed version this record names is refused
 * rather than stored.
 *
 * The same check makes it safe to guess. A record names the version that was compromised
 * but rarely the one before it, and the API that would list a project's releases is gone
 * for exactly the projects this corpus cares about -- wordpress.org closes a plugin after
 * an incident, and api.wordpress.org then answers 404 while downloads.wordpress.org still
 * serves every file. So `--phase before` walks the version number down a step at a time
 * and keeps the first archive that declares itself to be that release. A wrong guess
 * cannot be stored: it either 404s or fails to declare the version asked for.
 *
 * Clean bytes belong in `before` or `after`, never in `during` -- see
 * tools/verify-oss-samples.js.
 *
 *   node tools/acquire-wordpress-release.js [--phase before|after] [--only ID] [--dry-run]
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const yaml = require("js-yaml");
const { verificationFrom } = require("./normalize-basis.js");
const provenance = require("./provenance-store.js");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/acquire-wordpress-release.js [options]\n\n` +
    `  --only SUBSTRING   Restrict to incidents whose id or directory matches\n` +
    `  --dry-run          Report what would be collected and stop\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function records() {
  const found = [];
  const walk = dir => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name === "refs" || entry.name === "samples") continue;
      const child = path.join(dir, entry.name);
      if (fs.existsSync(path.join(child, "meta.yaml"))) found.push(child);
      walk(child);
    }
  };
  for (const scope of SCOPES) walk(scope);
  return found;
}

// candidates finds artifacts naming a fix on wordpress.org that no after sample covers.
/*
 * predecessors walks a version number down, lowest component first: 3.2.1 gives 3.2.0,
 * then 3.1.9 and 3.0.9 as the fallbacks for a project that skipped a release. Three steps
 * is enough to cross a gap without wandering into a different minor series, and every
 * candidate still has to declare itself before it is kept.
 */
function predecessors(version) {
  const parts = String(version).split(".");
  if (!parts.every(part => /^\d+$/.test(part))) return [];
  const out = [];
  let current = parts.map(Number);
  for (let step = 0; step < 3 && current; step += 1) {
    const next = current.slice();
    let index = next.length - 1;
    while (index >= 0 && next[index] === 0) {
      next[index] = 9;
      index -= 1;
    }
    if (index < 0) break;
    next[index] -= 1;
    out.push(next.join("."));
    current = next;
  }
  return out;
}

function candidates(only, phase) {
  const out = [];
  for (const dir of records()) {
    if (only && !dir.toLowerCase().includes(only)) continue;
    const doc = yaml.load(fs.readFileSync(path.join(dir, "meta.yaml"), "utf8")) || [];
    const manifestFile = path.join(dir, "samples", "manifest.yaml");
    const manifest = fs.existsSync(manifestFile)
      ? yaml.load(fs.readFileSync(manifestFile, "utf8")) || {} : {};
    const covered = new Set((manifest.samples || [])
      .filter(s => s.phase === phase).map(s => s.artifact_id));
    for (const entry of doc) {
      for (const artifact of entry.artifacts || []) {
        if (String(artifact.ecosystem || "").toLowerCase() !== "wordpress") continue;
        if (covered.has(artifact.id)) continue;
        const slug = String(artifact.package || artifact.id);
        if (phase === "after") {
          const fixed = (artifact.fixed_versions || []).map(String);
          if (!fixed.length) continue;
          out.push({ dir, incident: entry.id, artifact: artifact.id, slug, versions: [fixed[0]] });
        } else {
          const affected = (artifact.versions || []).map(String);
          if (!affected.length) continue;
          const versions = predecessors(affected[0]);
          if (versions.length) {
            out.push({ dir, incident: entry.id, artifact: artifact.id, slug, versions,
                       affected: affected[0] });
          }
        }
      }
    }
  }
  return out;
}

function fetch(url, destination) {
  try {
    execFileSync("curl", ["-sfL", "--max-time", "180", "-o", destination, url],
      { stdio: ["ignore", "ignore", "pipe"] });
    return fs.existsSync(destination) && fs.statSync(destination).size > 0;
  } catch {
    return false;
  }
}

// isZip reads the local file header rather than trusting the content type, since an
// error page served with a 200 would otherwise be stored as a release.
function isZip(file) {
  const head = Buffer.alloc(2);
  const fd = fs.openSync(file, "r");
  try {
    return fs.readSync(fd, head, 0, 2, 0) === 2 && head.toString("latin1") === "PK";
  } finally {
    fs.closeSync(fd);
  }
}

/*
 * declaresVersion reports whether the archive says it is the release we asked for.
 * A theme states this in style.css and a plugin in its readme's Stable tag or its main
 * file's Version header, so every text member near the top of the archive is checked
 * for a Version line naming the wanted release.
 */
function declaresVersion(archive, slug, version) {
  let listing;
  try {
    listing = execFileSync("unzip", ["-Z1", archive], { encoding: "utf8" }).split("\n");
  } catch {
    return null;
  }
  const wanted = listing.filter(name =>
    /(^|\/)(style\.css|readme\.txt|README\.txt)$/.test(name) ||
    new RegExp(`(^|/)${slug.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.php$`).test(name));
  for (const name of wanted) {
    let text;
    try {
      text = execFileSync("unzip", ["-p", archive, name], { encoding: "latin1", maxBuffer: 8 << 20 });
    } catch {
      continue;
    }
    const declared = text.match(/^\s*(?:\*\s*)?(?:Version|Stable tag):\s*(\S+)\s*$/im);
    if (declared && declared[1] === version) return name;
  }
  return null;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) usage(0);
  const dryRun = argv.includes("--dry-run");
  const onlyAt = argv.indexOf("--only");
  const only = onlyAt >= 0 ? String(argv[onlyAt + 1] || "").toLowerCase() : "";
  const phaseAt = argv.indexOf("--phase");
  const phase = phaseAt >= 0 ? String(argv[phaseAt + 1] || "") : "after";
  if (phase !== "before" && phase !== "after") usage(2);

  const targets = candidates(only, phase);
  process.stderr.write(`${targets.length} wordpress artifact(s) with no ${phase} sample and a ` +
    `version to look for\n`);
  let stored = 0;
  let refused = 0;
  let missing = 0;

  for (const target of targets) {
    const { dir, artifact, slug } = target;
    // Each candidate has to arrive as a zip and say it is the release asked for. The first
    // that does is the answer; the rest are versions the project never published.
    let version = null;
    let url = null;
    let declaredIn = null;
    let temporary = null;
    let sawArchive = false;
    for (const attempt of target.versions) {
      const name = `${slug}.${attempt}.zip`;
      const scratch = path.join(os.tmpdir(), `wp-${process.pid}-${name}`);
      let got = null;
      for (const candidate of [`https://downloads.wordpress.org/theme/${name}`,
                               `https://downloads.wordpress.org/plugin/${name}`]) {
        if (fetch(candidate, scratch) && isZip(scratch)) {
          got = candidate;
          break;
        }
      }
      if (!got) continue;
      sawArchive = true;
      const declared = declaresVersion(scratch, slug, attempt);
      if (!declared) {
        fs.unlinkSync(scratch);
        continue;
      }
      version = attempt;
      url = got;
      declaredIn = declared;
      temporary = scratch;
      break;
    }
    if (!version) {
      if (sawArchive) {
        refused += 1;
        process.stderr.write(`  REFUSED     ${slug}: ${target.versions.join(", ")} served an ` +
          `archive that does not declare that version\n`);
      } else {
        missing += 1;
        process.stderr.write(`  no release  ${slug}: tried ${target.versions.join(", ")}\n`);
      }
      continue;
    }
    const name = `${slug}.${version}.zip`;
    const body = fs.readFileSync(temporary);
    const digest = crypto.createHash("sha256").update(body).digest("hex");
    process.stderr.write(`  ok          ${slug}@${version} ${body.length} bytes (declared in ${declaredIn})\n`);
    if (dryRun) {
      fs.unlinkSync(temporary);
      continue;
    }

    const destinationDir = path.join(dir, "samples", artifact, phase);
    fs.mkdirSync(destinationDir, { recursive: true });
    const destination = path.join(destinationDir, name);
    if (fs.existsSync(destination)) fs.chmodSync(destination, 0o644);
    fs.renameSync(temporary, destination);
    fs.chmodSync(destination, 0o444);

    const retrievedAt = new Date().toISOString();
    provenance.record(path.join(dir, "samples"), digest, body.length, {
      schema_version: "1.0",
      artifact: { filename: name, sha256: digest, size_bytes: body.length },
      package: { ecosystem: "wordpress", name: slug, purl: `pkg:wordpress/${slug}@${version}` },
      fetch: { collector: "wordpress-release-recovery", category: "distribution", at: retrievedAt, url },
    });

    const manifestFile = path.join(dir, "samples", "manifest.yaml");
    const manifest = fs.existsSync(manifestFile)
      ? yaml.load(fs.readFileSync(manifestFile, "utf8")) || {} : { schema_version: 1, samples: [], unresolved: [] };
    manifest.samples ||= [];
    manifest.unresolved ||= [];
    const entry = {
      artifact_id: artifact,
      phase,
      classification: "clean",
      coordinate: `pkg:wordpress/${slug}@${version}`,
      version,
      filename: name,
      path: path.relative(path.join(dir, "samples"), destination),
      sha256: digest,
      size: body.length,
      source: { url, retrieved_at: retrievedAt, kind: "distribution" },
      verification: verificationFrom("probable_exact",
        ["official_distribution_endpoint", "archive_declares_version", "measured_sha256"]),
      notes: [phase === "after"
        ? `The remediated release this record names as the fix, served by wordpress.org, whose ` +
          `${path.basename(declaredIn)} declares version ${version}.`
        : `The release preceding the compromised ${target.affected}. wordpress.org no longer ` +
          `lists this project through its API, so the version was found by walking the number ` +
          `down from ${target.affected} and keeping the first archive whose ` +
          `${path.basename(declaredIn)} declares itself to be that release.`],
    };
    const key = item => [item.artifact_id, item.phase, item.filename].join(" ");
    manifest.samples = manifest.samples.filter(item => key(item) !== key(entry));
    manifest.samples.push(entry);
    fs.writeFileSync(manifestFile, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
    stored += 1;
  }

  process.stderr.write(`\n${stored} stored, ${refused} refused for not declaring the version, ` +
    `${missing} with no release served${dryRun ? " (dry run)" : ""}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`acquire-wordpress-release: ${error.message}\n`);
  process.exitCode = 1;
}
