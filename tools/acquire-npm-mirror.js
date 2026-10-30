#!/usr/bin/env node

/*
 * Recovers removed npm releases from caching registry mirrors.
 *
 * When npm unpublishes a malicious version the tarball stops being served, but the
 * corporate Nexus and Artifactory proxies that sit in front of npm keep whatever they
 * once fetched. Those caches are populated by ordinary installs, so a package with any
 * user in China or a CI runner behind one of these proxies still has its removed bytes
 * sitting on a public URL — the *published* bytes, not a reconstruction, which is what
 * separates this lane from the jsDelivr and socket.dev re-packing in
 * tools/acquire-oss-samples.js.
 *
 * A mirror is not authoritative about what it hands back, so nothing is stored until
 * the archive unpacks and its own package/package.json names the coordinate that was
 * asked for. That rejects the error pages, upstream 404 bodies, and stale
 * latest-version redirects these proxies otherwise return with a 200.
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const zlib = require("node:zlib");
const yaml = require("js-yaml");
const { verificationFrom } = require("./normalize-basis.js");
const provenance = require("./provenance-store.js");

const ROOT = path.resolve(__dirname, "..");
const ATTACKS = path.join(ROOT, "oss", "attacks");
const USER_AGENT = "supplychain-attack-data acquisition/1";

/*
 * The mirrors, in the order they are tried. Huawei Cloud is first because it retains
 * the deepest history of the three; npmmirror (Alibaba) answers for most of what the
 * Chinese frontend ecosystem installs; Tencent is last because it refuses some
 * regions outright with a 451 and so cannot be relied on.
 *
 * Each entry builds the candidate URLs for one release. Registries disagree about
 * whether a scoped package's tarball path repeats the scope, so both spellings are
 * offered and the first that verifies wins.
 */
const MIRRORS = [
  {
    id: "huaweicloud",
    urls: (name, version, base) => [
      `https://repo.huaweicloud.com/repository/npm/${name}/-/${base}-${version}.tgz`,
      `https://repo.huaweicloud.com/repository/npm/${name}/-/${name}-${version}.tgz`,
    ],
  },
  {
    id: "npmmirror",
    urls: (name, version, base) => [
      `https://registry.npmmirror.com/${name}/-/${base}-${version}.tgz`,
      `https://cdn.npmmirror.com/packages/${name}/${version}/${base}-${version}.tgz`,
    ],
  },
  {
    id: "tencent",
    urls: (name, version, base) => [
      `https://mirrors.cloud.tencent.com/npm/${name}/-/${base}-${version}.tgz`,
    ],
  },
];

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/acquire-npm-mirror.js [options]\n\n` +
    `  --only SUBSTRING   Restrict to incidents whose id or directory matches\n` +
    `  --phase PHASE      during (default) or after\n` +
    `  --limit N          Maximum releases attempted; 0 means unlimited\n` +
    `  --concurrency N    Concurrent mirror requests (default: 6)\n` +
    `  --retry            Re-attempt coordinates already recorded unresolved\n` +
    `  --dry-run          Report which releases a mirror still serves and stop\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = { phase: "during", limit: 0, concurrency: 6 };
  for (let i = 2; i < argv.length; i += 1) {
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) usage(1);
      i += 1;
      return next;
    };
    const arg = argv[i];
    if (arg === "--only") options.only = value().toLowerCase();
    else if (arg === "--phase") options.phase = value();
    else if (arg === "--limit") options.limit = Number(value());
    else if (arg === "--concurrency") options.concurrency = Math.max(1, Number(value()));
    else if (arg === "--retry") options.retry = true;
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--help" || arg === "-h") usage(0);
    else usage(1);
  }
  if (!["during", "after"].includes(options.phase)) usage(1);
  return options;
}

function walkMetaFiles(dir) {
  const found = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) found.push(...walkMetaFiles(file));
    else if (entry.name === "meta.yaml") found.push(file);
  }
  return found;
}

function stringValues(value) {
  if (!Array.isArray(value)) return [];
  return value.map(x => String(x).trim()).filter(Boolean);
}

// Records state a release's digests under hashes:, either as "sha256:<hex>" strings or
// as single-key mappings. Only SHA-256 matters here: it is what a downloaded archive is
// measured against, and a match is what makes the result exact rather than probable.
function reportedSha256(artifact) {
  const values = [];
  for (const item of artifact.hashes || []) {
    let value = "";
    if (typeof item === "string" && item.toLowerCase().startsWith("sha256:")) value = item.slice(7);
    else if (item && typeof item === "object" && item.sha256) value = String(item.sha256);
    value = value.trim().toLowerCase();
    if (/^[a-f0-9]{64}$/.test(value)) values.push(value);
  }
  return [...new Set(values)];
}

function encodeName(name) {
  return String(name).split("/").map(encodeURIComponent).join("/");
}

function safeSegment(value) {
  const result = String(value).replace(/[^A-Za-z0-9._@+-]+/g, "-").replace(/^-+|-+$/g, "");
  return result || "artifact";
}

// The stored name flattens the scope the way the rest of the corpus already spells it:
// @antv/g2 at 5.5.8 is antv-g2-5.5.8.tgz, so a directory listing sorts by package.
function sampleFilename(name, version) {
  return `${safeSegment(name.replace(/^@/, "").replace("/", "-"))}-${safeSegment(version)}.tgz`;
}

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

/*
 * loadTargets collects every npm release of the requested phase that the incident
 * records name. Reported SHA-256 values ride along: when a record states exactly one
 * digest for exactly one version, a match promotes the result from probable_exact to
 * exact.
 */
function loadTargets(options) {
  const targets = [];
  for (const metaPath of walkMetaFiles(ATTACKS)) {
    const attackDir = path.dirname(metaPath);
    const documents = yaml.load(fs.readFileSync(metaPath, "utf8"));
    for (const attack of Array.isArray(documents) ? documents : [documents]) {
      if (!attack || typeof attack !== "object") continue;
      const incidentId = String(attack.id || path.basename(attackDir));
      if (options.only && !`${incidentId} ${attackDir}`.toLowerCase().includes(options.only)) continue;
      for (const artifact of attack.artifacts || []) {
        if (String(artifact.ecosystem || "").trim().toLowerCase() !== "npm") continue;
        const name = String(artifact.package || artifact.name || artifact.id || "").trim();
        if (!name) continue;
        const versions = options.phase === "after"
          ? stringValues(artifact.fixed_versions)
          : stringValues(artifact.versions);
        const reported = reportedSha256(artifact);
        for (const version of versions) {
          targets.push({
            incidentId,
            attackDir,
            artifactId: String(artifact.id || name),
            name,
            version,
            purl: `pkg:npm/${encodeName(name)}@${encodeURIComponent(version)}`,
            phase: options.phase,
            classification: options.phase === "after" ? "remediated" : "affected",
            expectedSha256: versions.length === 1 && reported.length === 1 ? reported[0] : "",
          });
        }
      }
    }
  }
  return targets;
}

function manifestPath(target) {
  return path.join(target.attackDir, "samples", "manifest.yaml");
}

function loadManifest(target) {
  const file = manifestPath(target);
  if (!fs.existsSync(file)) return { schema_version: 1, samples: [], unresolved: [] };
  const value = yaml.load(fs.readFileSync(file, "utf8")) || {};
  value.samples ||= [];
  value.unresolved ||= [];
  return value;
}

function saveManifest(target, manifest) {
  const file = manifestPath(target);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
}

// A curated entry may pin an immutable revision with a PURL qualifier. That still names
// the same release, so keys compare the coordinate without it.
function entryKey(artifactId, phase, coordinate) {
  return `${artifactId}\u0000${phase}\u0000${String(coordinate || "").split("?", 1)[0]}`;
}

// Whether an unresolved entry already carries an attempt from this tool's mirrors.
function triedMirrors(entry) {
  return (entry.attempts || []).some(attempt => MIRRORS.some(mirror => String(attempt).startsWith(`${mirror.id}:`)));
}

function targetKey(target) {
  return entryKey(target.artifactId, target.phase, target.purl);
}

/*
 * A manifest is a whole-incident file, so acquiring 283 releases of one incident
 * serially would re-read and re-write it 283 times and lose entries whenever two
 * writes overlapped. Manifests are therefore held open for the run and flushed once
 * per incident at the end.
 */
const manifests = new Map();

function manifestFor(target) {
  const file = manifestPath(target);
  if (!manifests.has(file)) manifests.set(file, { target, manifest: loadManifest(target) });
  return manifests.get(file).manifest;
}

function flushManifests() {
  for (const { target, manifest } of manifests.values()) saveManifest(target, manifest);
}

async function fetchArchive(url, destination) {
  const response = await fetch(url, {
    headers: { "User-Agent": USER_AGENT },
    redirect: "follow",
    signal: AbortSignal.timeout(120000),
  });
  if (!response.ok) return `HTTP ${response.status}`;
  const body = Buffer.from(await response.arrayBuffer());
  // Every mirror in the list answers an upstream miss with a JSON or HTML body under a
  // 200 at least sometimes. A gzip magic check costs nothing and stops that early.
  if (body.length < 3 || body[0] !== 0x1f || body[1] !== 0x8b) return "not a gzip archive";
  fs.writeFileSync(destination, body);
  return null;
}

/*
 * describes returns the package.json a tarball carries, or null when the archive does
 * not unpack. Reading it through zlib and tar keeps the check to what the archive
 * itself says rather than what the URL promised.
 */
function packageManifestOf(file) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "npm-mirror-"));
  try {
    fs.writeFileSync(path.join(dir, "archive.tar"), zlib.gunzipSync(fs.readFileSync(file)));
    execFileSync("tar", ["-xf", "archive.tar", "-C", dir, "package/package.json"], { cwd: dir, stdio: "ignore" });
    return JSON.parse(fs.readFileSync(path.join(dir, "package", "package.json"), "utf8"));
  } catch (_) {
    return null;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function writeSidecar(destination, target, digest, size, url) {
  const sidecar = {
    schema_version: "1.0",
    artifact: { filename: path.basename(destination), sha256: digest, size_bytes: size },
    package: { ecosystem: "npm", name: target.name, version: target.version, purl: target.purl },
    fetch: {
      collector: "npm-mirror-recovery",
      category: "distribution_mirror",
      at: new Date().toISOString(),
      url,
      original_url: `https://registry.npmjs.org/${encodeName(target.name)}/-/${target.name.split("/").at(-1)}-${target.version}.tgz`,
      derivation: [
        "npm no longer serves this release; the mirror had cached the published tarball before it was removed.",
        "The archive unpacks and its package/package.json names this exact package and version, so the bytes are the published distribution rather than a rebuild.",
      ],
    },
  };
  provenance.recordFor(destination, sidecar);
}

function recordSuccess(target, temporary, url) {
  const digest = sha256File(temporary);
  const size = fs.statSync(temporary).size;
  const destinationDir = path.join(target.attackDir, "samples", safeSegment(target.artifactId), target.phase);
  fs.mkdirSync(destinationDir, { recursive: true });
  const destination = path.join(destinationDir, sampleFilename(target.name, target.version));
  fs.renameSync(temporary, destination);
  writeSidecar(destination, target, digest, size, url);

  const manifest = manifestFor(target);
  manifest.samples = manifest.samples.filter(x => entryKey(x.artifact_id, x.phase, x.coordinate) !== targetKey(target));
  manifest.unresolved = manifest.unresolved.filter(x => entryKey(x.artifact_id, x.phase, x.coordinate) !== targetKey(target));
  manifest.samples.push({
    artifact_id: target.artifactId,
    phase: target.phase,
    classification: target.classification,
    coordinate: target.purl,
    version: target.version,
    filename: path.basename(destination),
    path: path.relative(path.join(target.attackDir, "samples"), destination),
    sha256: digest,
    size,
    source: { url, original_url: `https://registry.npmjs.org/${encodeName(target.name)}/-/${target.name.split("/").at(-1)}-${target.version}.tgz`, retrieved_at: new Date().toISOString(), kind: "distribution_mirror" },
    verification: target.expectedSha256 && target.expectedSha256 === digest
      ? verificationFrom("exact", ["reported_sha256", "measured_sha256"])
      : verificationFrom("probable_exact",
          ["distribution_mirror_retained_published_tarball", "exact_package_name_and_version", "measured_sha256"]),
  });
  return digest;
}

function recordFailure(target, attempts) {
  const manifest = manifestFor(target);
  let entry = manifest.unresolved.find(x => entryKey(x.artifact_id, x.phase, x.coordinate) === targetKey(target));
  if (!entry) {
    entry = { artifact_id: target.artifactId, phase: target.phase, coordinate: target.purl, status: "unavailable", attempts: [] };
    manifest.unresolved.push(entry);
  }
  entry.status = "unavailable";
  entry.last_attempted_at = new Date().toISOString();
  entry.attempts ||= [];
  for (const attempt of attempts) if (!entry.attempts.includes(attempt)) entry.attempts.push(attempt);
}

async function acquire(target, options) {
  const base = target.name.split("/").at(-1);
  const attempts = [];
  for (const mirror of MIRRORS) {
    for (const url of mirror.urls(encodeName(target.name), encodeURIComponent(target.version), base)) {
      const temporary = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "npm-mirror-")), "archive.tgz");
      let failure;
      try {
        failure = await fetchArchive(url, temporary);
      } catch (error) {
        failure = error.name === "TimeoutError" ? "timed out" : String(error.message || error);
      }
      if (!failure) {
        const packaged = packageManifestOf(temporary);
        if (!packaged) failure = "archive did not unpack";
        else if (packaged.name !== target.name || String(packaged.version) !== target.version) {
          failure = `archive declares ${packaged.name}@${packaged.version}`;
        }
      }
      if (failure) {
        attempts.push(`${mirror.id}: ${failure}`);
        fs.rmSync(path.dirname(temporary), { recursive: true, force: true });
        continue;
      }
      if (options.dryRun) {
        fs.rmSync(path.dirname(temporary), { recursive: true, force: true });
        return { status: "available", url };
      }
      const digest = recordSuccess(target, temporary, url);
      fs.rmSync(path.dirname(temporary), { recursive: true, force: true });
      return { status: "acquired", url, digest };
    }
  }
  if (!options.dryRun) recordFailure(target, attempts);
  return { status: "unavailable", attempts };
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

async function main() {
  const options = parseArgs(process.argv);
  const all = loadTargets(options);

  const queue = all.filter(target => {
    const manifest = manifestFor(target);
    const key = targetKey(target);
    if (manifest.samples.some(x => entryKey(x.artifact_id, x.phase, x.coordinate) === key)) return false;
    // Only a prior mirror attempt suppresses a retry. An entry left unresolved by the
    // Forager lanes says nothing about whether a mirror still holds the release.
    if (!options.retry && manifest.unresolved.some(x => entryKey(x.artifact_id, x.phase, x.coordinate) === key && triedMirrors(x))) return false;
    return true;
  });
  const targets = options.limit > 0 ? queue.slice(0, options.limit) : queue;
  process.stderr.write(`${all.length} ${options.phase} npm releases in scope, ${queue.length} without a sample, attempting ${targets.length}\n`);

  let acquired = 0;
  let unavailable = 0;
  await mapLimit(targets, options.concurrency, async (target, index) => {
    const result = await acquire(target, options);
    if (result.status === "unavailable") unavailable += 1;
    else acquired += 1;
    process.stderr.write(`[${index + 1}/${targets.length}] ${result.status} ${target.purl}${result.url ? ` <- ${result.url}` : ""}\n`);
  });

  if (!options.dryRun) flushManifests();
  process.stderr.write(`\n${acquired} recovered, ${unavailable} not held by any mirror\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exit(1);
});
