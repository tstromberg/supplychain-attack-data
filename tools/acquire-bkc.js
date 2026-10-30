#!/usr/bin/env node

/*
 * Recover compromised npm releases from a Backstabber's Knife Collection mirror.
 *
 * BKC (Ohm et al.) is an academic dataset of malicious packages. It reaches releases no
 * other lane does: npm removes an unpublished version from the registry and from its own
 * packument, mirrors sync the removal, and the malware repositories never held a package
 * archive in the first place. For 2018-era removals every other lane in this repository
 * comes back empty. The dataset's public distribution now requires an institutional access
 * request, so this reads a local mirror rather than fetching.
 *
 * Identity cannot come from a digest here. Once a version is unpublished npm drops its
 * `dist` block, so there is no publisher digest left to reproduce, and an archive that has
 * passed through a research dataset may have been repacked. So each candidate has to
 * declare itself: the archive is refused unless its own package.json names exactly the
 * package and version the record says was compromised. That check is the whole safeguard,
 * and it is why nothing here is recorded as `exact`.
 *
 * Where a record already states a digest for the release and the archive does not
 * reproduce it, the archive wins: it names itself as the affected release, while a stated
 * digest that nothing can be checked against is the weaker claim. The disagreement is
 * written into the sample's notes rather than quietly resolved, because only the record's
 * own sources can say where that digest came from.
 *
 *   node tools/acquire-bkc.js                    report what is recoverable
 *   node tools/acquire-bkc.js --apply            store it
 *   node tools/acquire-bkc.js --only tanstack    limit to records matching a substring
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const yaml = require("js-yaml");
const provenance = require("./provenance-store.js");
const { verificationFrom } = require("./normalize-basis.js");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];
const DEFAULT_MIRROR = "smaug:/data/samples/bad/datasets/various/Backstabber's Knife " +
  "Collection/Backstabber's Knife Collection/samples/npm";

const COMPLETE = new Set(["exact", "probable_exact", "tree_equivalent", "checksum_verified",
  "source_snapshot"]);

function parseArgs(argv) {
  const options = { mirror: DEFAULT_MIRROR, apply: false, only: "" };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--apply") options.apply = true;
    else if (argv[i] === "--mirror") options.mirror = argv[++i];
    else if (argv[i] === "--only") options.only = String(argv[++i] || "").toLowerCase();
    else if (argv[i] === "--help" || argv[i] === "-h") {
      process.stdout.write("Usage: node tools/acquire-bkc.js [--apply] [--mirror HOST:PATH] " +
        "[--only SUBSTRING]\n");
      process.exit(0);
    }
  }
  return options;
}

/*
 * A remote mirror is addressed over ssh, a local one read directly. Quoting is the only
 * real difference, and getting it wrong on a path that contains both a space and an
 * apostrophe is how this would silently read nothing at all.
 */
function remote(mirror) {
  if (mirror.startsWith("/")) return null;
  const split = mirror.indexOf(":");
  return split < 0 ? null : { host: mirror.slice(0, split), base: mirror.slice(split + 1) };
}

const shellQuote = value => `'${String(value).split("'").join(`'\\''`)}'`;

function readArchive(options, pkg, version) {
  const where = remote(options.mirror);
  const dir = where ? `${where.base}/${pkg}/${version}` : path.join(options.mirror, pkg, version);
  try {
    if (!where) {
      const name = fs.readdirSync(dir).find(file => file.endsWith(".tgz"));
      return name ? { name, body: fs.readFileSync(path.join(dir, name)) } : null;
    }
    const listing = execFileSync("ssh", [where.host, `ls -1 -- ${shellQuote(dir)}`],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    const name = listing.split("\n").map(line => line.trim())
      .find(line => line.endsWith(".tgz"));
    if (!name) return null;
    const body = execFileSync("ssh", [where.host, `cat -- ${shellQuote(`${dir}/${name}`)}`],
      { maxBuffer: 512 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] });
    return { name, body };
  } catch {
    return null;
  }
}

/*
 * declares reads the archive's own package.json. This is the only thing standing between
 * the corpus and a mislabelled research sample, so a candidate that cannot be unpacked, or
 * that names a different package or version, is refused rather than stored with a caveat.
 */
function declares(body, pkg, version) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bkc-"));
  const archive = path.join(temp, "candidate.tgz");
  try {
    fs.writeFileSync(archive, body);
    execFileSync("tar", ["xzf", archive, "-C", temp, "package/package.json"], { stdio: "ignore" });
    const declared = JSON.parse(fs.readFileSync(path.join(temp, "package", "package.json"), "utf8"));
    return {
      ok: String(declared.name) === pkg && String(declared.version) === version,
      name: declared.name, version: declared.version, scripts: declared.scripts || {},
    };
  } catch (error) {
    return { ok: false, error: String(error.message).split("\n")[0] };
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
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

// gaps lists the compromised npm releases the corpus names but does not hold.
function gaps(only) {
  const out = [];
  for (const dir of records()) {
    const recordId = path.relative(ROOT, dir).split(path.sep).pop();
    if (only && !recordId.toLowerCase().includes(only)) continue;
    const meta = yaml.load(fs.readFileSync(path.join(dir, "meta.yaml"), "utf8")) || [];
    const manifest = yaml.load(
      fs.readFileSync(path.join(dir, "samples", "manifest.yaml"), "utf8")) || {};

    const held = new Set();
    for (const sample of manifest.samples || []) {
      if (sample.phase !== "during") continue;
      if (!COMPLETE.has(String((sample.verification || {}).status || ""))) continue;
      const versions = Array.isArray(sample.version) ? sample.version : [sample.version];
      for (const version of versions) {
        if (version) held.add(JSON.stringify([sample.artifact_id, String(version)]));
      }
    }
    for (const item of meta) {
      for (const artifact of item.artifacts || []) {
        if (String(artifact.ecosystem || "").toLowerCase() !== "npm") continue;
        const pkg = String(artifact.package || artifact.name || artifact.id);
        for (const version of artifact.versions || []) {
          if (held.has(JSON.stringify([artifact.id, String(version)]))) continue;
          out.push({
            dir, recordId, artifact: artifact.id, pkg, version: String(version),
            stated: (artifact.hashes || []).map(String)
              .filter(hash => hash.startsWith("sha256:")).map(hash => hash.slice(7)),
          });
        }
      }
    }
  }
  return out;
}

function main() {
  const options = parseArgs(process.argv);
  const wanted = gaps(options.only);
  const found = [];
  const refused = [];
  let absent = 0;

  for (const gap of wanted) {
    const archive = readArchive(options, gap.pkg, gap.version);
    if (!archive) {
      absent += 1;
      continue;
    }
    const identity = declares(archive.body, gap.pkg, gap.version);
    if (!identity.ok) {
      refused.push(`${gap.pkg}@${gap.version}: archive declares ` +
        `${identity.name || "?"}@${identity.version || "?"}` +
        `${identity.error ? ` (${identity.error})` : ""}`);
      continue;
    }
    const digest = crypto.createHash("sha256").update(archive.body).digest("hex");
    found.push({ ...gap, archive, digest, identity,
      contradicts: gap.stated.length > 0 && !gap.stated.includes(digest) });
  }

  const out = process.stdout;
  const contradicting = found.filter(item => item.contradicts);
  out.write(`${wanted.length} compromised npm release(s) the records name but do not hold\n`);
  out.write(`  recoverable from the mirror:  ${found.length}\n`);
  out.write(`  not in the mirror:            ${absent}\n`);
  out.write(`  refused, identity mismatch:   ${refused.length}\n`);
  out.write(`  contradicting a stated digest: ${contradicting.length}\n`);
  for (const item of contradicting) {
    out.write(`      ${item.recordId} ${item.pkg}@${item.version}: archive ` +
      `${item.digest.slice(0, 16)} vs stated ${item.stated.map(h => h.slice(0, 16)).join(", ")}\n`);
  }
  for (const item of refused.slice(0, 10)) out.write(`      ${item}\n`);

  if (!options.apply) {
    const byRecord = new Map();
    for (const item of found) byRecord.set(item.recordId, (byRecord.get(item.recordId) || 0) + 1);
    out.write(`\nrecoverable, by record:\n`);
    for (const [record, count] of [...byRecord].sort((a, b) => b[1] - a[1])) {
      out.write(`  ${String(count).padStart(4)}  ${record}\n`);
    }
    out.write(`\nreport only; pass --apply to store\n`);
    return;
  }

  const at = new Date().toISOString();
  const touched = new Set();
  let stored = 0;
  for (const item of found) {
    const relative = path.join(item.artifact, "during", item.archive.name);
    const destination = path.join(item.dir, "samples", relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, item.archive.body);
    fs.chmodSync(destination, 0o444);

    const hooks = Object.entries(item.identity.scripts)
      .filter(([name]) => /^(pre|post)?install$/.test(name))
      .map(([name, body]) => `${name}: ${body}`);

    const manifestFile = path.join(item.dir, "samples", "manifest.yaml");
    const manifest = yaml.load(fs.readFileSync(manifestFile, "utf8")) || {};
    manifest.samples ||= [];
    const entry = {
      artifact_id: item.artifact, phase: "during", classification: "malicious",
      coordinate: `pkg:npm/${item.pkg}@${item.version}`, version: item.version,
      filename: item.archive.name, path: relative,
      sha256: item.digest, size: item.archive.body.length,
      source: {
        url: `local:${options.mirror}/${item.pkg}/${item.version}/${item.archive.name}`,
        original_url: `https://registry.npmjs.org/${item.pkg}/-/${item.archive.name}`,
        retrieved_at: at, kind: "research_corpus",
      },
      verification: verificationFrom("probable_exact", [
        "archive_package_json_declares_the_affected_name_and_version",
        "research_corpus_retained_archive",
        ...(hooks.length ? ["package_json_declares_an_install_hook"] : []),
        "measured_sha256_and_size",
      ]),
      notes: [
        "Recovered from a mirror of the Backstabber's Knife Collection, the academic dataset " +
        "of malicious packages published by Ohm et al. npm unpublished this release, so the " +
        "registry, its mirrors and the malware repositories no longer serve it.",
        `Identity rests on the archive rather than on a digest: its package.json declares ` +
        `${item.pkg} ${item.version}` +
        (hooks.length ? `, and it carries ${hooks.join("; ")}.` : "."),
        "It is probable_exact rather than exact because npm drops the dist block for an " +
        "unpublished version, so no publisher digest survives to reproduce.",
      ],
      subject: item.artifact,
    };
    /*
     * Where the record already states a digest for the release and this archive does not
     * reproduce it, the archive wins. It declares the affected package and version in its
     * own package.json and comes from a curated dataset that collected from the registry;
     * a stated digest that nothing can now be checked against is the weaker claim. The
     * discrepancy is written down rather than quietly resolved, because the stated digest
     * may still be the better record of what npm served and only the record's own sources
     * can settle that.
     */
    if (item.contradicts) {
      entry.notes.push(`These bytes do not reproduce the sha256 this record states for the ` +
        `release (${item.stated.join(", ")}). The archive is taken as the artifact: it names ` +
        `itself as the affected release, while the stated digest cannot be checked against ` +
        `anything now that npm's packument carries no dist block for the version. The stated ` +
        `digest is left in the record so the disagreement stays visible.`);
    }
    manifest.samples = manifest.samples.filter(sample => sample.path !== relative);
    manifest.samples.push(entry);
    fs.writeFileSync(manifestFile,
      yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
    touched.add(manifestFile);

    provenance.recordFor(destination, {
      schema_version: "1.0",
      artifact: { filename: item.archive.name, sha256: item.digest,
        size_bytes: item.archive.body.length },
      package: { ecosystem: "npm", name: item.pkg, version: item.version,
        purl: `pkg:npm/${item.pkg}@${item.version}` },
      fetch: {
        collector: "backstabbers-knife-collection-mirror", category: "research_corpus", at,
        url: `local:${options.mirror}/${item.pkg}/${item.version}/${item.archive.name}`,
        original_url: `https://registry.npmjs.org/${item.pkg}/-/${item.archive.name}`,
        derivation: [
          "npm unpublished this release; the registry, its mirrors and the malware " +
          "repositories return nothing for it.",
          "Taken from a local mirror of the Backstabber's Knife Collection, stored exactly " +
          "as the dataset holds it.",
          `Accepted because the archive's package.json declares ${item.pkg} ${item.version}.`,
        ],
      },
    });
    stored += 1;
  }
  out.write(`\nstored ${stored} release(s) across ${touched.size} manifest(s)\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`acquire-bkc: ${error.stack || error.message}\n`);
  process.exitCode = 1;
}
