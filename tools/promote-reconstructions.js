#!/usr/bin/env node

/*
 * Replaces npm reconstructions with the published bytes, wherever a mirror still has them.
 *
 * A reconstruction is a stand-in: jsDelivr and socket.dev serve a package's files
 * individually, and re-packing them yields an archive whose members are right and
 * whose bytes npm never served. The caching registry mirrors are a different kind of
 * source — they hold the tarball as published — and the corpus reconstructed a great
 * many releases before that lane existed. This asks the mirrors for each one.
 *
 * Two things can come back, and neither leaves a reconstruction standing:
 *
 *   - The mirror's bytes equal the held bytes. Then the archive was never a
 *     reconstruction, whatever it was named: re-packing happened to reproduce the
 *     published tarball exactly. It is renamed and recorded as the distribution it is.
 *   - The mirror's bytes differ. Then the published archive is now available and
 *     supersedes a rebuild of it. The original is stored and the reconstruction is
 *     removed, because two near-identical archives where one is synthetic is how a
 *     synthetic one ends up cited as evidence.
 *
 * Reconstructions no mirror can answer for are left exactly as they are.
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");
const { execFileSync } = require("node:child_process");
const yaml = require("js-yaml");
const { verificationFrom } = require("./normalize-basis.js");
const provenance = require("./provenance-store.js");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];
const USER_AGENT = "supplychain-attack-data acquisition/1";

// The same mirrors, in the same order, as tools/acquire-npm-mirror.js.
const MIRRORS = [
  "https://repo.huaweicloud.com/repository/npm",
  "https://registry.npmmirror.com",
  "https://r.cnpmjs.org",
  "https://mirrors.cloud.tencent.com/npm",
];

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/promote-reconstructions.js [options]\n\n` +
    `  --only SUBSTRING   Restrict to incidents whose id or directory matches\n` +
    `  --limit N          Maximum reconstructions examined; 0 means unlimited\n` +
    `  --concurrency N    Concurrent mirror requests (default: 6)\n` +
    `  --dry-run          Report what would change and stop\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = { limit: 0, concurrency: 6 };
  for (let i = 2; i < argv.length; i += 1) {
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) usage(1);
      i += 1;
      return next;
    };
    const arg = argv[i];
    if (arg === "--only") options.only = value().toLowerCase();
    else if (arg === "--limit") options.limit = Number(value());
    else if (arg === "--concurrency") options.concurrency = Math.max(1, Number(value()));
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--help" || arg === "-h") usage(0);
    else usage(1);
  }
  return options;
}

function encodeName(name) {
  return String(name).split("/").map(encodeURIComponent).join("/");
}

function safeSegment(value) {
  const result = String(value).replace(/[^A-Za-z0-9._@+-]+/g, "-").replace(/^-+|-+$/g, "");
  return result || "artifact";
}

function distributionFilename(name, version) {
  return `${safeSegment(name.replace(/^@/, "").replace("/", "-"))}-${safeSegment(version)}.tgz`;
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

/*
 * candidates finds every npm sample the corpus records as a reconstruction. The status
 * is what defines one, not the filename: some were stored under the ordinary name and
 * only the manifest says they were rebuilt.
 */
function candidates(options) {
  const found = [];
  for (const scope of SCOPES) {
    for (const entry of fs.readdirSync(scope, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isDirectory()) continue;
      const dir = path.join(scope, entry.name);
      const manifestFile = path.join(dir, "samples", "manifest.yaml");
      if (!fs.existsSync(manifestFile)) continue;
      if (options.only && !`${entry.name} ${dir}`.toLowerCase().includes(options.only)) continue;
      const manifest = yaml.load(fs.readFileSync(manifestFile, "utf8")) || {};
      for (const sample of manifest.samples || []) {
        const reconstructed = sample.verification?.status === "tree_equivalent" ||
          String(sample.source?.kind || "").includes("reconstruct");
        const coordinate = String(sample.coordinate || "");
        if (!reconstructed || !coordinate.startsWith("pkg:npm/")) continue;
        const at = coordinate.lastIndexOf("@");
        if (at < 0) continue;
        found.push({
          incident: entry.name,
          dir,
          manifestFile,
          sample,
          name: decodeURIComponent(coordinate.slice("pkg:npm/".length, at)),
          version: decodeURIComponent(coordinate.slice(at + 1)),
        });
      }
    }
  }
  return found;
}

// The archive's own package.json, or null when the bytes are not that archive. Every
// mirror answers an upstream miss with a page under a 200 at least sometimes.
function declaredCoordinate(body) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "promote-"));
  try {
    fs.writeFileSync(path.join(scratch, "archive.tar"), zlib.gunzipSync(body));
    execFileSync("tar", ["-xf", "archive.tar", "-C", scratch, "package/package.json"], { cwd: scratch, stdio: "ignore" });
    const manifest = JSON.parse(fs.readFileSync(path.join(scratch, "package", "package.json"), "utf8"));
    return { name: manifest.name, version: String(manifest.version) };
  } catch (_) {
    return null;
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

async function publishedCopy(name, version) {
  const base = name.split("/").at(-1);
  for (const mirror of MIRRORS) {
    const url = `${mirror}/${encodeName(name)}/-/${base}-${version}.tgz`;
    let body;
    try {
      const response = await fetch(url, {
        headers: { "User-Agent": USER_AGENT },
        redirect: "follow",
        signal: AbortSignal.timeout(120000),
      });
      if (!response.ok) continue;
      body = Buffer.from(await response.arrayBuffer());
    } catch (_) {
      continue;
    }
    if (body.length < 3 || body[0] !== 0x1f || body[1] !== 0x8b) continue;
    const declared = declaredCoordinate(body);
    if (!declared || declared.name !== name || declared.version !== version) continue;
    return { url, body, sha256: sha256(body) };
  }
  return null;
}

function canonicalTarballURL(name, version) {
  return `https://registry.npmjs.org/${encodeName(name)}/-/${name.split("/").at(-1)}-${version}.tgz`;
}

/*
 * rewrite records the sample as the distribution it now is. The reconstruction chain
 * goes: it described how bytes were rebuilt, and these bytes were not.
 */
function rewrite(item, copy, filename, identical) {
  const { sample } = item;
  item.previousPath = sample.path;
  const originalURL = canonicalTarballURL(item.name, item.version);
  sample.filename = filename;
  sample.path = path.join(path.dirname(sample.path), filename);
  sample.sha256 = copy.sha256;
  sample.size = copy.body.length;
  sample.source = {
    url: copy.url,
    original_url: originalURL,
    retrieved_at: new Date().toISOString(),
    kind: "distribution_mirror",
  };
  // An entry that already carried per-member verification keeps it. Those bases —
  // every member matched against jsDelivr's independent inventory, named IOCs present —
  // say more about the archive than the mirror does, and replacing them with the
  // mirror's generic basis would lose evidence in the course of correcting a status.
  const carried = (sample.verification?.evidence || sample.verification?.basis || [])
    .filter(x => !/^official_distribution_endpoint$/.test(x));
  sample.verification = verificationFrom("probable_exact", [...new Set([
    "distribution_mirror_retained_published_tarball",
    "exact_package_name_and_version",
    ...carried,
    "measured_sha256",
  ])]);
  const note = identical
    ? "Recorded as tree_equivalent until 2026-09-10 although these bytes came from a registry mirror " +
      "that still had the published tarball. Re-fetched and found unchanged, so the status was wrong " +
      "rather than the bytes: this is the published archive, not a reconstruction of one. Any note " +
      "below calling the container digest mirror-specific is superseded — a caching proxy serves the " +
      "tarball it cached and does not re-pack one, so the container is npm's."
    : "Replaced the reconstruction held until 2026-09-10: a registry mirror still serves the published " +
      "tarball, and these are those bytes. The rebuilt archive it supersedes was removed rather than " +
      "kept beside it, so a synthetic copy cannot be mistaken for the distribution.";
  // Every prior note still stands except the one asserting these bytes are synthetic,
  // which is exactly what stopped being true.
  sample.notes = [note, ...(sample.notes || []).filter(x => !/^Synthetic archive:/i.test(String(x)))];
  return sample;
}

function writeSidecar(file, item, copy) {
  provenance.recordFor(file, {
    schema_version: "1.0",
    artifact: { filename: path.basename(file), sha256: copy.sha256, size_bytes: copy.body.length },
    package: {
      ecosystem: "npm",
      name: item.name,
      version: item.version,
      purl: `pkg:npm/${encodeName(item.name)}@${encodeURIComponent(item.version)}`,
    },
    fetch: {
      collector: "npm-mirror-recovery",
      category: "distribution_mirror",
      at: new Date().toISOString(),
      url: copy.url,
      original_url: canonicalTarballURL(item.name, item.version),
      derivation: [
        "npm no longer serves this release; the mirror had cached the published tarball before it was removed.",
        "The archive unpacks and its package/package.json names this exact package and version.",
      ],
    },
  });
}

function store(item, copy, identical) {
  const samplesDir = path.join(item.dir, "samples");
  const previous = path.join(samplesDir, item.sample.path);
  const filename = distributionFilename(item.name, item.version);
  const destination = path.join(path.dirname(previous), filename);

  if (fs.existsSync(previous) && previous !== destination) {
    fs.chmodSync(previous, 0o644);
    fs.rmSync(previous);
    // The provenance of the superseded bytes is keyed on their digest and stays where it
    // is: it records an acquisition that genuinely happened, whatever the corpus later
    // decided to hold. Only the auxiliary member listing travels with the file.
    if (fs.existsSync(`${previous}.partial.json`)) fs.rmSync(`${previous}.partial.json`);
  }
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  if (fs.existsSync(destination)) fs.chmodSync(destination, 0o644);
  fs.writeFileSync(destination, copy.body);
  fs.chmodSync(destination, 0o444);
  writeSidecar(destination, item, copy);
  rewrite(item, copy, filename, identical);
}

async function mapLimit(items, limit, worker) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next; next += 1;
      out[i] = await worker(items[i], i);
    }
  }));
  return out;
}

async function main() {
  const options = parseArgs(process.argv);
  const all = candidates(options);
  const queue = options.limit > 0 ? all.slice(0, options.limit) : all;
  process.stderr.write(`${all.length} npm reconstructions recorded, examining ${queue.length}\n`);

  const touched = new Map();
  let identical = 0;
  let superseded = 0;
  let unanswered = 0;
  let failed = 0;

  await mapLimit(queue, options.concurrency, async (item, index) => {
    const copy = await publishedCopy(item.name, item.version);
    if (!copy) {
      unanswered += 1;
      process.stderr.write(`[${index + 1}/${queue.length}] no mirror copy ${item.sample.coordinate}\n`);
      return;
    }
    const same = copy.sha256 === item.sample.sha256;
    if (same) identical += 1; else superseded += 1;
    process.stderr.write(`[${index + 1}/${queue.length}] ${same ? "identical" : "superseded"} ` +
      `${item.sample.coordinate} <- ${copy.url}\n`);
    if (options.dryRun) return;
    try {
      store(item, copy, same);
      touched.set(item.manifestFile, true);
    } catch (error) {
      // One unwritable path must not abandon the rest of the pass, and must not be
      // counted as a success: the manifest is only updated for what was stored.
      if (same) identical -= 1; else superseded -= 1;
      failed += 1;
      process.stderr.write(`[${index + 1}/${queue.length}] could not store ${item.sample.coordinate}: ${error.message}\n`);
    }
  });

  flush(options, queue, touched);
  process.stderr.write(`\n${identical} were already the published bytes, ${superseded} replaced by them, ` +
    `${unanswered} left as reconstructions` + (failed ? `, ${failed} could not be stored` : "") + `\n`);
}

function flush(options, queue, touched) {
  if (!options.dryRun) {
    // One manifest holds every sample of an incident, so it is written once at the end
    // rather than per sample; the entry objects were edited in place.
    for (const manifestFile of touched.keys()) {
      const manifest = yaml.load(fs.readFileSync(manifestFile, "utf8"));
      for (const item of queue) {
        if (item.manifestFile !== manifestFile || !item.previousPath) continue;
        // Matched on the path it had before the rewrite: an artifact can hold several
        // samples of one coordinate — a tarball beside an extracted fragment — and the
        // stored path is the only field that tells them apart.
        const at = manifest.samples.findIndex(x => x.path === item.previousPath);
        if (at >= 0) manifest.samples[at] = item.sample;
      }
      fs.writeFileSync(manifestFile, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
    }
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exit(1);
});
