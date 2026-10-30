#!/usr/bin/env node

/*
 * Collects the remediated WordPress.org release an artifact names as its fix.
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
 * Clean bytes belong in `after`, never in `during` -- see tools/verify-oss-samples.js.
 *
 *   node tools/acquire-wordpress-release.js [--only ID] [--dry-run]
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
function candidates(only) {
  const out = [];
  for (const dir of records()) {
    if (only && !dir.toLowerCase().includes(only)) continue;
    const doc = yaml.load(fs.readFileSync(path.join(dir, "meta.yaml"), "utf8")) || [];
    const manifestFile = path.join(dir, "samples", "manifest.yaml");
    const manifest = fs.existsSync(manifestFile)
      ? yaml.load(fs.readFileSync(manifestFile, "utf8")) || {} : {};
    const covered = new Set((manifest.samples || [])
      .filter(s => s.phase === "after").map(s => s.artifact_id));
    for (const entry of doc) {
      for (const artifact of entry.artifacts || []) {
        if (String(artifact.ecosystem || "").toLowerCase() !== "wordpress") continue;
        const fixed = (artifact.fixed_versions || []).map(String);
        if (!fixed.length || covered.has(artifact.id)) continue;
        out.push({ dir, incident: entry.id, artifact: artifact.id,
                   slug: String(artifact.package || artifact.id), version: fixed[0] });
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

  const targets = candidates(only);
  process.stderr.write(`${targets.length} artifact(s) name a wordpress.org fix with no after sample\n`);
  let stored = 0;
  let refused = 0;
  let missing = 0;

  for (const target of targets) {
    const { dir, artifact, slug, version } = target;
    const name = `${slug}.${version}.zip`;
    const temporary = path.join(os.tmpdir(), `wp-${process.pid}-${name}`);
    const urls = [
      `https://downloads.wordpress.org/theme/${name}`,
      `https://downloads.wordpress.org/plugin/${name}`,
    ];
    let url = null;
    for (const candidate of urls) {
      if (fetch(candidate, temporary) && isZip(temporary)) {
        url = candidate;
        break;
      }
    }
    if (!url) {
      missing += 1;
      process.stderr.write(`  no release  ${slug}@${version}\n`);
      continue;
    }
    const declaredIn = declaresVersion(temporary, slug, version);
    if (!declaredIn) {
      refused += 1;
      fs.unlinkSync(temporary);
      process.stderr.write(`  REFUSED     ${slug}@${version}: archive does not declare this version\n`);
      continue;
    }
    const body = fs.readFileSync(temporary);
    const digest = crypto.createHash("sha256").update(body).digest("hex");
    process.stderr.write(`  ok          ${slug}@${version} ${body.length} bytes (declared in ${declaredIn})\n`);
    if (dryRun) {
      fs.unlinkSync(temporary);
      continue;
    }

    const destinationDir = path.join(dir, "samples", artifact, "after");
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
      phase: "after",
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
      notes: [`The remediated release this record names as the fix, served by wordpress.org, whose ` +
              `${path.basename(declaredIn)} declares version ${version}.`],
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
