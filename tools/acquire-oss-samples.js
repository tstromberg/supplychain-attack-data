#!/usr/bin/env node

/*
 * Build and optionally fetch the open-source sample inventory.
 *
 * This tool only downloads package archives. It never imports, installs, or
 * executes their contents. Forager owns registry/archive/provider fallbacks and
 * writes the adjacent .forage.json provenance record.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const yaml = require("js-yaml");
const { compressLargeSample } = require("./sample-storage.js");

const ROOT = path.resolve(__dirname, "..");
const ATTACKS = path.join(ROOT, "oss", "attacks");
const DEFAULT_FORAGER = "/private/tmp/forager-purl";
const REPORT = path.join(ROOT, "OSS_SAMPLE_COVERAGE.yaml");

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/acquire-oss-samples.js [options]\n\n` +
    `  --fetch                 Download targets (default: inventory only)\n` +
    `  --ecosystem LIST        Comma-separated ecosystems (default: npm,pypi)\n` +
    `  --limit N               Maximum targets attempted; 0 means unlimited\n` +
    `  --concurrency N         Concurrent Forager processes (default: 1)\n` +
    `  --batch N               PURL targets per Forager process (default: 20)\n` +
    `  --timeout N             Per-target timeout in seconds (default: 600)\n` +
    `  --live-only             Queue only releases still served by npm/PyPI\n` +
    `  --hopper URL            Try this Hopper for unambiguous SHA-256 targets\n` +
    `  --forager PATH          Forager binary (default: ${DEFAULT_FORAGER})\n` +
    `  --no-before             Do not discover/fetch predecessor releases\n` +
    `  --before-only           Queue predecessors only, for acquired affected samples\n` +
    `  --no-after              Do not queue known fixed/remediated releases\n` +
    `  --after-only            Queue known fixed/remediated releases only\n` +
    `  --hash-only             Fetch every reported digest via Hopper/providers\n` +
    `  --partial               Keep incomplete reconstructions as payload_only\n` +
    `  --only SUBSTRING        Restrict to incidents whose directory matches\n` +
    `  --retry                 Retry coordinates already recorded unresolved\n` +
    `  --report PATH           Coverage report path\n` +
    `  --help                  Show this help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = {
    fetch: false,
    ecosystems: new Set(["npm", "pypi"]),
    limit: 0,
    // Forager's per-domain pacing is per process, so each additional concurrent
    // process multiplies the request rate against the same host. Batch instead.
    concurrency: 1,
    batch: 20,
    // Removed npm releases are recovered by re-packing socket.dev's file listing,
    // which is rate limited to one file per 15 seconds. A whole package routinely
    // needs five minutes. A short timeout records a live target as unavailable.
    timeout: 600,
    liveOnly: false,
    hopper: "",
    forager: DEFAULT_FORAGER,
    before: true,
    beforeOnly: false,
    after: true,
    afterOnly: false,
    hashOnly: false,
    partial: false,
    only: "",
    retry: false,
    report: REPORT,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      if (++i >= argv.length) usage(2);
      return argv[i];
    };
    if (arg === "--fetch") options.fetch = true;
    else if (arg === "--ecosystem") options.ecosystems = new Set(value().split(",").map(x => x.trim()).filter(Boolean));
    else if (arg === "--limit") options.limit = Number.parseInt(value(), 10);
    else if (arg === "--concurrency") options.concurrency = Number.parseInt(value(), 10);
    else if (arg === "--batch") options.batch = Number.parseInt(value(), 10);
    else if (arg === "--timeout") options.timeout = Number.parseInt(value(), 10);
    else if (arg === "--live-only") options.liveOnly = true;
    else if (arg === "--hopper") options.hopper = value().replace(/\/$/, "");
    else if (arg === "--forager") options.forager = path.resolve(value());
    else if (arg === "--no-before") options.before = false;
    else if (arg === "--before-only") options.beforeOnly = true;
    else if (arg === "--no-after") options.after = false;
    else if (arg === "--after-only") options.afterOnly = true;
    else if (arg === "--hash-only") options.hashOnly = true;
    else if (arg === "--partial") options.partial = true;
    else if (arg === "--only") options.only = value();
    else if (arg === "--retry") options.retry = true;
    else if (arg === "--report") options.report = path.resolve(value());
    else if (arg === "--help" || arg === "-h") usage(0);
    else usage(2);
  }
  if (!Number.isInteger(options.limit) || options.limit < 0) usage(2);
  if (!Number.isInteger(options.concurrency) || options.concurrency < 1 || options.concurrency > 16) usage(2);
  if (!Number.isInteger(options.batch) || options.batch < 1 || options.batch > 200) usage(2);
  if (!Number.isInteger(options.timeout) || options.timeout < 10 || options.timeout > 3600) usage(2);
  if (options.beforeOnly) options.before = true;
  if (options.afterOnly) {
    options.after = true;
    options.before = false;
  }
  if (options.hashOnly) {
    options.before = false;
    options.after = false;
  }
  return options;
}

function walkMetaFiles(dir) {
  const result = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) result.push(...walkMetaFiles(file));
    else if (entry.name === "meta.yaml") result.push(file);
  }
  return result.sort();
}

function arrayRoot(value) {
  return Array.isArray(value) ? value : [value];
}

function stringValues(value) {
  if (!Array.isArray(value)) return [];
  return value.map(String).map(x => x.trim()).filter(Boolean);
}

// Reports on older incidents often publish only an MD5 or SHA-1, and MalwareBazaar
// indexes all three, so every algorithm Forager resolves is worth carrying.
const DIGEST_LENGTHS = { md5: 32, sha1: 40, sha256: 64 };

function digestValues(artifact) {
  const values = [];
  for (const item of artifact.hashes || []) {
    for (const [algorithm, length] of Object.entries(DIGEST_LENGTHS)) {
      let value = "";
      if (typeof item === "string" && item.toLowerCase().startsWith(`${algorithm}:`)) {
        value = item.slice(algorithm.length + 1);
      } else if (item && typeof item === "object" && item[algorithm]) {
        value = String(item[algorithm]);
      }
      value = value.trim().toLowerCase();
      if (new RegExp(`^[a-f0-9]{${length}}$`).test(value)) values.push({ algorithm, value });
    }
  }
  return [...new Map(values.map(x => [`${x.algorithm}:${x.value}`, x])).values()];
}

function sha256Values(artifact) {
  return digestValues(artifact).filter(x => x.algorithm === "sha256").map(x => x.value);
}

function encodeName(name) {
  return String(name).split("/").map(encodeURIComponent).join("/");
}

function coordinate(ecosystem, name, version) {
  const n = encodeName(name);
  const v = encodeURIComponent(String(version));
  if (ecosystem === "npm") return `pkg:npm/${n}@${v}`;
  if (ecosystem === "pypi") return `pkg:pypi/${n}@${v}`;
  if (ecosystem === "packagist") return `pkg:composer/${n}@${v}`;
  // Incident records name the plugin directory both ways.
  if (ecosystem === "wordpress" || ecosystem === "wordpress.org") return `pkg:wordpress/${n}@${v}`;
  if (ecosystem === "github") return `pkg:github/${n}@${v}`;
  if (ecosystem === "rubygems") return `pkg:gem/${n}@${v}`;
  if (["vscode", "vscode_marketplace", "vscode marketplace", "vs code marketplace"].includes(ecosystem)) {
    return `pkg:vscode-extension/${n}@${v}`;
  }
  if (ecosystem === "aur") return `pkg:alpm/aur/${n}@${v}`;
  return null;
}

// Incidents whose affected coordinate no longer serves the affected bytes. Fetching
// one of these yields a comparator, and recording it as the during state would assert
// malicious content nobody acquired. Coverage counts them as comparator_only.
const RESTORED_DISTRIBUTIONS = {
  "accesspress-themes": {
    match: (ecosystem, kind) => ecosystem === "wordpress" && kind === "plugin",
    note: "Clean same-version comparator from WordPress.org; the AccessPress vendor-site ZIP was the compromised distribution.",
  },
  "laravel-lang": {
    match: ecosystem => ecosystem === "packagist",
    note: "Laravel-Lang restored every rewritten tag after cleanup, so the archive Packagist serves for this version today is the pre-attack commit, not the re-tagged malicious one.",
  },
  "intercom-php": {
    match: ecosystem => ecosystem === "packagist",
    note: "Packagist resolves this version to a commit predating the April 30 overwrite, so the archive is a same-version comparator rather than the affected state.",
  },
};

function loadInventory() {
  const attacks = [];
  const targets = [];
  const remediationTargets = [];
  const hashTargets = [];
  for (const metaPath of walkMetaFiles(ATTACKS)) {
    const attackDir = path.dirname(metaPath);
    const documents = arrayRoot(yaml.load(fs.readFileSync(metaPath, "utf8")));
    for (const attack of documents) {
      if (!attack || typeof attack !== "object") continue;
      const incidentId = String(attack.id || path.basename(attackDir));
      attacks.push({ incidentId, attackDir, metaPath });
      for (const artifact of attack.artifacts || []) {
        const ecosystem = String(artifact.ecosystem || "").trim().toLowerCase();
        const name = String(artifact.package || artifact.name || artifact.id || "").trim();
        const artifactKind = String(artifact.kind || "").trim().toLowerCase();
        const versions = stringValues(artifact.versions);
        const fixedVersions = stringValues(artifact.fixed_versions);
        const digests = digestValues(artifact);
        const hashes = sha256Values(artifact);
        for (const { algorithm, value } of digests) {
          hashTargets.push({
            incidentId,
            attackDir,
            artifactId: String(artifact.id || name),
            ecosystem,
            name,
            artifactKind,
            version: versions.length === 1 ? versions[0] : "",
            purl: `${algorithm}:${value}`,
            phase: "during",
            classification: "affected",
            expectedDigest: { algorithm, value },
            expectedSha256: algorithm === "sha256" ? value : "",
            reportedSha256: algorithm === "sha256" ? [value] : [],
            hashOnly: true,
          });
        }
        for (const version of versions) {
          // pkg:wordpress maps to the plugin distribution service. Themes use
          // a different archive/SVN namespace and must not accidentally resolve
          // to an unrelated plugin that happens to share the slug.
          const purl = ecosystem === "wordpress" && artifactKind === "theme" ? null : coordinate(ecosystem, name, version);
          const restored = RESTORED_DISTRIBUTIONS[incidentId];
          const cleanComparator = Boolean(restored?.match(ecosystem, artifactKind));
          targets.push({
            incidentId,
            attackDir,
            artifactId: String(artifact.id || name),
            ecosystem,
            name,
            artifactKind,
            version,
            purl,
            phase: "during",
            classification: cleanComparator ? "clean" : "affected",
            notes: cleanComparator ? [restored.note] : [],
            // Only one-to-one evidence is safe to assert without additional research.
            expectedSha256: versions.length === 1 && hashes.length === 1 ? hashes[0] : "",
            reportedSha256: hashes,
          });
        }
        for (const version of fixedVersions) {
          const purl = ecosystem === "wordpress" && artifactKind === "theme" ? null : coordinate(ecosystem, name, version);
          remediationTargets.push({
            incidentId,
            attackDir,
            artifactId: String(artifact.id || name),
            ecosystem,
            name,
            artifactKind,
            version,
            purl,
            phase: "after",
            classification: "remediated",
            expectedSha256: "",
            reportedSha256: [],
            relatesTo: versions,
            notes: ["Known fixed/remediated release identified by the incident record."],
          });
        }
      }
    }
  }
  return { attacks, targets, remediationTargets, hashTargets };
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

function sampleKey(target) {
  return `${target.artifactId}\u0000${target.phase}\u0000${target.purl}`;
}

// A curated entry may pin an immutable revision with a PURL qualifier, as the WordPress
// SVN and Composer tag samples do. That still names the same package version, so keys
// ignore the qualifier. Comparing the full string instead makes a rerun miss the
// existing sample and append a duplicate beside it.
function entryKey(entry) {
  const coordinate = String(entry.coordinate || "").split("?", 1)[0];
  return `${entry.artifact_id}\u0000${entry.phase}\u0000${coordinate}`;
}

function manifestState(target) {
  const manifest = loadManifest(target);
  const sample = manifest.samples.find(x => entryKey(x) === sampleKey(target) ||
    (target.hashOnly && x.artifact_id === target.artifactId && x.phase === target.phase && x.sha256 === target.expectedSha256));
  const unresolved = manifest.unresolved.find(x => entryKey(x) === sampleKey(target));
  return { manifest, sample, unresolved };
}

function manifestCoverageState(target) {
  const state = manifestState(target);
  if (target.hashOnly) return state;

  // Immutable source revisions use PURL qualifiers to retain exact revision
  // provenance. They still cover the underlying package version. Prefer
  // incident evidence over clean same-version comparators so comparator bytes
  // cannot make malicious-sample coverage look complete.
  const matches = state.manifest.samples.filter(x =>
    x.artifact_id === target.artifactId &&
    x.phase === target.phase &&
    String(x.coordinate || "").split("?", 1)[0] === target.purl);
  const comparatorClasses = new Set(["clean", "baseline_candidate", "remediated"]);
  const sample = matches.find(x => !comparatorClasses.has(x.classification));
  const comparator = matches.find(x => comparatorClasses.has(x.classification));
  return { ...state, sample, comparator };
}

function safeSegment(value) {
  const result = String(value).replace(/[^A-Za-z0-9._@+-]+/g, "-").replace(/^-+|-+$/g, "");
  return result || "artifact";
}

function digestFile(file, algorithm = "sha256") {
  const hash = crypto.createHash(algorithm);
  hash.update(fs.readFileSync(file));
  return hash.digest("hex");
}

function sha256File(file) {
  return digestFile(file, "sha256");
}

function run(command, args, options = {}) {
  return new Promise(resolve => {
    const { timeoutMs = 0, ...spawnOptions } = options;
    const child = spawn(command, args, { ...spawnOptions, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = timeoutMs ? setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, timeoutMs) : null;
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", error => resolve({ code: -1, stdout, stderr: `${stderr}${error.message}` }));
    child.on("close", code => {
      if (timer) clearTimeout(timer);
      resolve({ code: timedOut ? 124 : code, stdout, stderr: timedOut ? `${stderr}\nper-target timeout` : stderr });
    });
  });
}

// Forager renamed its digest flag from -sha256 to -hash. Passing the wrong spelling
// makes it print usage and exit non-zero, which looks exactly like "sample not found",
// so ask the binary in hand which one it takes.
let hashFlagCache = "";
async function hashFlag(forager) {
  if (hashFlagCache) return hashFlagCache;
  const help = await run(forager, ["fetch", "--help"], { timeoutMs: 15000 });
  hashFlagCache = /-{1,2}hash\b/.test(`${help.stdout}${help.stderr}`) ? "--hash" : "--sha256";
  return hashFlagCache;
}

async function getJSON(url) {
  const response = await fetch(url, {
    headers: { Accept: "application/json", "User-Agent": "supplychain-attack-data acquisition/1" },
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function wordpressSVNTags(slug) {
  const url = `https://plugins.svn.wordpress.org/${encodeURIComponent(slug)}/tags/`;
  const response = await fetch(url, {
    method: "PROPFIND",
    headers: { Depth: "1", "User-Agent": "supplychain-attack-data acquisition/1" },
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error(`WordPress SVN HTTP ${response.status}`);
  const xml = await response.text();
  const releases = [];
  for (const block of xml.match(/<D:response\b[\s\S]*?<\/D:response>/g) || []) {
    const href = block.match(/<D:href>([^<]+)<\/D:href>/)?.[1] || "";
    const marker = `/${slug}/tags/`;
    const offset = href.indexOf(marker);
    if (offset < 0) continue;
    const version = decodeURIComponent(href.slice(offset + marker.length).replace(/\/$/, ""));
    if (!version) continue;
    const created = block.match(/<(?:lp1:)?creationdate>([^<]+)<\/(?:lp1:)?creationdate>/)?.[1] || "";
    const revision = block.match(/<(?:lp1:)?version-name>([^<]+)<\/(?:lp1:)?version-name>/)?.[1] || "";
    const author = block.match(/<(?:lp1:)?creator-displayname>([^<]+)<\/(?:lp1:)?creator-displayname>/)?.[1] || "";
    releases.push({ version, time: Date.parse(created), created, revision, author, svnURL: `${url}${encodeURIComponent(version)}/` });
  }
  return releases;
}

function latestEarlierRelease(releases, affectedVersions) {
  const affected = new Set(affectedVersions);
  const affectedTimes = releases.filter(x => affected.has(x.version) && x.time).map(x => x.time);
  if (affectedTimes.length === 0) return null;
  const firstAffected = Math.min(...affectedTimes);
  return releases
    .filter(x => !affected.has(x.version) && x.time && x.time < firstAffected)
    .sort((a, b) => b.time - a.time)[0] || null;
}

async function discoverPredecessor(group) {
  const first = group[0];
  const affectedVersions = group.map(x => x.version);
  if (first.ecosystem === "npm") {
    const packument = await getJSON(`https://registry.npmjs.org/${encodeName(first.name)}`);
    const releases = Object.keys(packument.versions || {}).map(version => ({
      version,
      time: Date.parse((packument.time || {})[version]),
    }));
    return latestEarlierRelease(releases, affectedVersions);
  }
  if (first.ecosystem === "pypi") {
    const project = await getJSON(`https://pypi.org/pypi/${encodeURIComponent(first.name)}/json`);
    const releases = Object.entries(project.releases || {}).map(([version, files]) => ({
      version,
      time: Math.min(...files.map(x => Date.parse(x.upload_time_iso_8601 || x.upload_time)).filter(Number.isFinite)),
    }));
    return latestEarlierRelease(releases, affectedVersions);
  }
  if (first.ecosystem === "wordpress" && first.artifactKind !== "theme") {
    return latestEarlierRelease(await wordpressSVNTags(first.name), affectedVersions);
  }
  return null;
}

async function addPredecessors(targets, selectedEcosystems, acquiredOnly = false) {
  const groups = new Map();
  for (const target of targets) {
    if (!selectedEcosystems.has(target.ecosystem) || !target.purl) continue;
    const evidence = manifestCoverageState(target).sample;
    if (target.classification === "clean" && !evidence) continue;
    if (acquiredOnly) {
      const acquired = evidence;
      if (!acquired || acquired.classification === "clean") continue;
    }
    const key = `${target.attackDir}\u0000${target.artifactId}\u0000${target.ecosystem}\u0000${target.name}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(target);
  }
  const predecessors = [];
  await mapLimit([...groups.values()], 8, async group => {
    try {
      const release = await discoverPredecessor(group);
      if (!release) return;
      const source = group[0];
      predecessors.push({
        ...source,
        version: release.version,
        purl: coordinate(source.ecosystem, source.name, release.version),
        phase: "before",
        classification: "baseline_candidate",
        expectedSha256: "",
        reportedSha256: [],
        relatesTo: group.map(x => x.version),
        notes: [
          ...(release.revision ? [`Selected from WordPress SVN tag revision ${release.revision}.`] : []),
          ...(release.created ? [`WordPress SVN tag timestamp: ${release.created}.`] : []),
          ...(release.author ? [`WordPress SVN tag author: ${release.author}.`] : []),
          ...(release.svnURL ? [`WordPress SVN tag: ${release.svnURL}`] : []),
        ],
      });
    } catch (error) {
      process.stderr.write(`predecessor ${group[0].name}: ${error.message}\n`);
    }
  });
  return predecessors;
}

function npmTarballURL(target) {
  const filename = target.name.split("/").at(-1);
  return `https://registry.npmjs.org/${target.name}/-/${filename}-${target.version}.tgz`;
}

async function isLiveRelease(target) {
  try {
    if (target.ecosystem === "npm") {
      const response = await fetch(npmTarballURL(target), {
        method: "HEAD",
        headers: { "User-Agent": "supplychain-attack-data acquisition/1" },
        signal: AbortSignal.timeout(15000),
      });
      return response.ok;
    }
    if (target.ecosystem === "pypi") {
      const response = await fetch(`https://pypi.org/pypi/${encodeURIComponent(target.name)}/${encodeURIComponent(target.version)}/json`, {
        method: "GET",
        headers: { Accept: "application/json", "User-Agent": "supplychain-attack-data acquisition/1" },
        signal: AbortSignal.timeout(15000),
      });
      return response.ok;
    }
  } catch (_) {
    return false;
  }
  return false;
}

async function filterLiveTargets(targets) {
  const results = await mapLimit(targets, 16, async target => ({ target, live: await isLiveRelease(target) }));
  return results.filter(x => x.live).map(x => x.target);
}

function findDownloadedFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const found = [];
  const walk = current => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const file = path.join(current, entry.name);
      if (entry.isDirectory()) walk(file);
      else if (!entry.name.endsWith(".forage.json") && !entry.name.endsWith(".partial.json")) found.push(file);
    }
  };
  walk(dir);
  return found;
}

function sourceKind(url) {
  if (/web\.archive\.org\/web\//.test(url)) return "web_archive";
  if (/archive\.softwareheritage\.org/.test(url)) return "source_archive";
  // socket.dev serves a package's files individually. Forager re-packs them into
  // a tarball, so the bytes are a reconstruction, never the published archive.
  if (/socket\.dev|socketusercontent\.com/.test(url)) return "reconstructed_distribution";
  if (/cdn\.jsdelivr\.net|unpkg\.com/.test(url)) return "reconstructed_distribution";
  if (/\/api\/file\//.test(url)) return "research_corpus";
  if (/bazaar\.abuse\.ch/.test(url)) return "malware_repository";
  if (/tria\.ge/.test(url)) return "malware_sandbox";
  return "distribution";
}

function verification(target, sidecar, digest, file) {
  const url = sidecar.fetch?.url || "";
  if (target.expectedSha256 && digest === target.expectedSha256) {
    return { status: "exact", basis: ["reported_sha256", "measured_sha256"] };
  }
  // An MD5 or SHA-1 target binds the bytes just as tightly for this purpose: the
  // reported digest is what identified the sample, and SHA-256 is measured anyway.
  const expected = target.expectedDigest;
  if (expected && expected.algorithm !== "sha256" && digestFile(file, expected.algorithm) === expected.value) {
    return { status: "exact", basis: [`reported_${expected.algorithm}`, "measured_sha256"] };
  }
  if (/archive\.softwareheritage\.org|cdn\.jsdelivr\.net|unpkg\.com/.test(url)) {
    return { status: "tree_equivalent", basis: ["reconstructed_archived_source_tree", "measured_sha256"] };
  }
  if (/socket\.dev|socketusercontent\.com/.test(url)) {
    return { status: "tree_equivalent", basis: ["reconstructed_socket_dev_file_listing", "measured_sha256"] };
  }
  if (/web\.archive\.org\/web\//.test(url)) {
    return { status: "probable_exact", basis: ["wayback_original_replay", "measured_sha256"] };
  }
  return { status: "probable_exact", basis: ["official_distribution_endpoint", "measured_sha256"] };
}

function recordSuccess(target, downloaded) {
  const sidecarFile = `${downloaded}.forage.json`;
  const sidecar = fs.existsSync(sidecarFile) ? JSON.parse(fs.readFileSync(sidecarFile, "utf8")) : {};
  const digest = sha256File(downloaded);
  const ext = path.basename(downloaded).includes(".") ? path.basename(downloaded).slice(path.basename(downloaded).indexOf(".")) : ".sample";
  let filename = path.basename(downloaded);
  const destinationDir = path.join(target.attackDir, "samples", safeSegment(target.artifactId), target.phase);
  fs.mkdirSync(destinationDir, { recursive: true });
  let destination = path.join(destinationDir, filename);
  if (fs.existsSync(destination) && sha256File(destination) !== digest) {
    filename = `${safeSegment(target.name)}-${safeSegment(target.version)}-${digest.slice(0, 12)}${ext}`;
    destination = path.join(destinationDir, filename);
  }
  if (!fs.existsSync(destination)) fs.renameSync(downloaded, destination);
  if (fs.existsSync(sidecarFile)) {
    const destinationSidecar = `${destination}.forage.json`;
    if (!fs.existsSync(destinationSidecar)) fs.renameSync(sidecarFile, destinationSidecar);
  }
  // An incomplete reconstruction carries an accounting record naming the members
  // the source could no longer serve. It moves with the bytes, like the sidecar.
  const partialFile = `${downloaded}.partial.json`;
  let partial = null;
  if (fs.existsSync(partialFile)) {
    partial = JSON.parse(fs.readFileSync(partialFile, "utf8"));
    const destinationPartial = `${destination}.partial.json`;
    if (!fs.existsSync(destinationPartial)) fs.renameSync(partialFile, destinationPartial);
  }

  // Identity is the artifact's own bytes; large ones are stored compressed.
  const artifactSize = fs.statSync(destination).size;
  const stored = compressLargeSample(destination);

  const { manifest } = manifestState(target);
  manifest.samples = manifest.samples.filter(x => entryKey(x) !== sampleKey(target));
  manifest.unresolved = manifest.unresolved.filter(x => entryKey(x) !== sampleKey(target));
  const fetchInfo = sidecar.fetch || {};
  const entry = {
    artifact_id: target.artifactId,
    phase: target.phase,
    classification: target.classification,
    coordinate: target.purl,
    version: target.version,
    filename,
    path: path.relative(path.join(target.attackDir, "samples"), stored.path),
    sha256: digest,
    size: artifactSize,
    source: {
      url: fetchInfo.url || "unknown",
      retrieved_at: fetchInfo.at || new Date().toISOString(),
      kind: sourceKind(fetchInfo.url || ""),
    },
    ...(stored.storage ? { storage: stored.storage } : {}),
    verification: partial
      ? { status: "payload_only", basis: ["partial_reconstruction", "measured_sha256"] }
      : verification(target, sidecar, digest, destination),
  };
  if (fetchInfo.original_url) entry.source.original_url = fetchInfo.original_url;
  if (target.relatesTo?.length) entry.relates_to = target.relatesTo.map(version => ({ phase: "during", version }));
  if (target.notes?.length) entry.notes = target.notes;
  if (partial) {
    entry.notes = [...(entry.notes || []),
      `Reconstruction recovered ${partial.recovered} of ${partial.listed} listed members. Absent: ${partial.missing.join(", ")}. This is not the published archive.`];
  }
  manifest.samples.push(entry);
  saveManifest(target, manifest);
  return entry;
}

// A timeout is not evidence of unavailability. Recording it as such once caused a
// short run to bury hundreds of recoverable releases under status: unavailable.
function recordFailure(target, attempts, status = "unavailable") {
  const { manifest } = manifestState(target);
  let entry = manifest.unresolved.find(x => entryKey(x) === sampleKey(target));
  if (!entry) {
    entry = { artifact_id: target.artifactId, phase: target.phase, coordinate: target.purl, status, attempts: [] };
    manifest.unresolved.push(entry);
  }
  entry.status = status;
  entry.last_attempted_at = new Date().toISOString();
  entry.attempts ||= [];
  for (const attempt of attempts) if (!entry.attempts.includes(attempt)) entry.attempts.push(attempt);
  saveManifest(target, manifest);
}

async function fetchTarget(target, options, ordinal, total) {
  const state = manifestState(target);
  if (state.sample) return { status: "existing", target };
  // A prior timeout produced no answer about the target, so it never suppresses a retry.
  if (state.unresolved && state.unresolved.status !== "timed_out" && !options.retry) {
    return { status: "unresolved_existing", target };
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "oss-acquire-"));
  const common = ["fetch", "-o", tempDir];
  const attempts = [];
  const withHash = Boolean(target.expectedDigest?.value || target.expectedSha256);
  let args = [...common];
  if (withHash) {
    if (options.hopper) args.push("--hopper", options.hopper);
    args.push(await hashFlag(options.forager), target.expectedDigest?.value || target.expectedSha256);
  }
  if (!target.hashOnly) args.push(target.purl);
  process.stderr.write(`[${ordinal}/${total}] ${target.phase} ${target.purl}${withHash && !target.hashOnly ? " + sha256" : ""}\n`);
  let result = await run(options.forager, args, { cwd: ROOT, timeoutMs: options.timeout * 1000, env: foragerEnv(options) });
  attempts.push(`Forager PURL${withHash ? "/SHA-256" : ""}: ${result.code === 0 ? "completed" : result.stderr.trim().split("\n").slice(-1)[0] || `exit ${result.code}`}`);

  // A package may have multiple distributions whose selected registry file does
  // not match a reported hash. Preserve the package release in that case, while
  // retaining the mismatch in the manifest attempt history.
  if (result.code !== 0 && withHash && !target.hashOnly) {
    result = await run(options.forager, [...common, target.purl], { cwd: ROOT, timeoutMs: options.timeout * 1000, env: foragerEnv(options) });
    attempts.push(`Forager PURL without hash constraint: ${result.code === 0 ? "completed" : result.stderr.trim().split("\n").slice(-1)[0] || `exit ${result.code}`}`);
  }

  const files = findDownloadedFiles(tempDir);
  if (result.code === 0 && files.length === 1) {
    const entry = recordSuccess(target, files[0]);
    fs.rmSync(tempDir, { recursive: true, force: true });
    return { status: "downloaded", target, entry };
  }
  if (files.length > 1) attempts.push(`Forager produced ${files.length} candidate files; automatic mapping was refused.`);
  const timedOut = result.code === 124;
  recordFailure(target, attempts, timedOut ? "timed_out" : "unavailable");
  fs.rmSync(tempDir, { recursive: true, force: true });
  return { status: timedOut ? "timed_out" : "failed", target, attempts };
}

// Forager paces requests per domain, but that state lives in the process. Running one
// process per target restarts the limiter every time, so a long queue sends an unpaced
// first request per target and any concurrency multiplies the rate against the same
// host. socket.dev started returning 403 after such a run. Passing many PURLs to one
// process keeps a single limiter across the whole batch.
// Forager keeps an incomplete reconstruction only when asked. Without this the
// socket.dev lane yields nothing for a package whose CDN lost a member.
function foragerEnv(options) {
  return options.partial ? { ...process.env, FORAGER_ALLOW_PARTIAL: "1" } : process.env;
}

function purlKey(purl) {
  const value = String(purl || "");
  try {
    return decodeURIComponent(value).toLowerCase();
  } catch (_) {
    return value.toLowerCase();
  }
}

async function fetchBatch(targets, options, startOrdinal, total) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "oss-acquire-"));
  const args = ["fetch", "-o", tempDir, ...targets.map(x => x.purl)];
  const last = startOrdinal + targets.length - 1;
  process.stderr.write(`[${startOrdinal}-${last}/${total}] batch of ${targets.length}\n`);
  const result = await run(options.forager, args, { cwd: ROOT, timeoutMs: options.timeout * 1000 * targets.length, env: foragerEnv(options) });

  // Map bytes back to targets through the capture sidecar rather than by filename.
  const byPurl = new Map(targets.map(x => [purlKey(x.purl), x]));
  const claimed = new Set();
  const results = [];
  for (const file of findDownloadedFiles(tempDir)) {
    const sidecarFile = `${file}.forage.json`;
    if (!fs.existsSync(sidecarFile)) continue;
    let purl = "";
    try {
      purl = JSON.parse(fs.readFileSync(sidecarFile, "utf8")).package?.purl || "";
    } catch (_) {
      continue;
    }
    const target = byPurl.get(purlKey(purl));
    if (!target || claimed.has(target)) continue;
    claimed.add(target);
    results.push({ status: "downloaded", target, entry: recordSuccess(target, file) });
  }

  const timedOut = result.code === 124;
  const tail = result.stderr.trim().split("\n").at(-1) || `exit ${result.code}`;
  for (const target of targets) {
    if (claimed.has(target)) continue;
    const key = purlKey(target.purl);
    const specific = result.stderr.split("\n").filter(line => purlKey(line).includes(key)).at(-1);
    const attempts = [`Forager batch: ${timedOut ? "per-target timeout" : specific || tail}`];
    recordFailure(target, attempts, timedOut ? "timed_out" : "unavailable");
    results.push({ status: timedOut ? "timed_out" : "failed", target, attempts });
  }
  fs.rmSync(tempDir, { recursive: true, force: true });
  return results;
}

function chunk(items, size) {
  const groups = [];
  for (let i = 0; i < items.length; i += size) groups.push(items.slice(i, i + size));
  return groups;
}

async function mapLimit(items, concurrency, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

function currentCoverage(inventory, selectedEcosystems) {
  const selected = inventory.targets.filter(x => selectedEcosystems.has(x.ecosystem) && x.purl);
  const counts = { acquired: 0, comparator_only: 0, unresolved: 0, timed_out: 0, pending: 0 };
  const byEcosystem = {};
  for (const target of selected) {
    byEcosystem[target.ecosystem] ||= { targets: 0, acquired: 0, comparator_only: 0, unresolved: 0, timed_out: 0, pending: 0 };
    byEcosystem[target.ecosystem].targets += 1;
    const state = manifestCoverageState(target);
    // A timed-out target is still an open question, not a negative result.
    const unresolvedStatus = state.unresolved?.status === "timed_out" ? "timed_out" : "unresolved";
    const status = state.sample ? "acquired" : state.comparator ? "comparator_only" : state.unresolved ? unresolvedStatus : "pending";
    counts[status] += 1;
    byEcosystem[target.ecosystem][status] += 1;
  }
  return { selected, counts, byEcosystem };
}

function corpusSummary() {
  const summary = {
    manifests: 0,
    acquired_files: 0,
    unresolved_records: 0,
    total_bytes: 0,
    by_phase: {},
    by_classification: {},
    by_verification: {},
    by_source_kind: {},
  };
  for (const file of walkMetaFiles(ATTACKS)) {
    const manifestFile = path.join(path.dirname(file), "samples", "manifest.yaml");
    if (!fs.existsSync(manifestFile)) continue;
    summary.manifests += 1;
    const manifest = yaml.load(fs.readFileSync(manifestFile, "utf8")) || {};
    summary.unresolved_records += (manifest.unresolved || []).length;
    for (const sample of manifest.samples || []) {
      summary.acquired_files += 1;
      summary.total_bytes += Number(sample.size || 0);
      const phase = sample.phase || "unknown";
      const classification = sample.classification || "unknown";
      const verificationStatus = sample.verification?.status || "unknown";
      const kind = sample.source?.kind || "unknown";
      summary.by_phase[phase] = (summary.by_phase[phase] || 0) + 1;
      summary.by_classification[classification] = (summary.by_classification[classification] || 0) + 1;
      summary.by_verification[verificationStatus] = (summary.by_verification[verificationStatus] || 0) + 1;
      summary.by_source_kind[kind] = (summary.by_source_kind[kind] || 0) + 1;
    }
  }
  return summary;
}

function hashCoverage(inventory) {
  const counts = { observations: inventory.hashTargets.length, acquired: 0, unresolved: 0, pending: 0 };
  const byAlgorithm = {};
  for (const target of inventory.hashTargets) {
    const algorithm = target.expectedDigest?.algorithm || "sha256";
    byAlgorithm[algorithm] = (byAlgorithm[algorithm] || 0) + 1;
    const state = manifestState(target);
    if (state.sample) counts.acquired += 1;
    else if (state.unresolved) counts.unresolved += 1;
    else counts.pending += 1;
  }
  counts.unique_digests = new Set(inventory.hashTargets.map(x => x.purl)).size;
  counts.by_algorithm = Object.fromEntries(Object.entries(byAlgorithm).sort());
  return counts;
}

function remediationCoverage(inventory, selectedEcosystems) {
  const selected = inventory.remediationTargets.filter(x => selectedEcosystems.has(x.ecosystem) && x.purl);
  const counts = { targets: selected.length, acquired: 0, unresolved: 0, pending: 0 };
  for (const target of selected) {
    const state = manifestState(target);
    if (state.sample) counts.acquired += 1;
    else if (state.unresolved) counts.unresolved += 1;
    else counts.pending += 1;
  }
  return counts;
}

function writeReport(options, inventory, results, predecessors) {
  const coverage = currentCoverage(inventory, options.ecosystems);
  const addressableEcosystems = new Set(inventory.targets.filter(x => x.purl).map(x => x.ecosystem));
  const globalCoverage = currentCoverage(inventory, addressableEcosystems);
  const allEcosystems = {};
  for (const target of inventory.targets) allEcosystems[target.ecosystem || "unknown"] = (allEcosystems[target.ecosystem || "unknown"] || 0) + 1;
  const report = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    scope: "open-source attacks",
    policy: {
      layout: "oss/attacks/<incident>/samples/<artifact>/{before,during,after}",
      provenance: "Adjacent .forage.json files are mandatory for acquired files.",
      safety: "Archives are stored only; this workflow never imports, installs, or executes them.",
      fidelity: {
        exact: "Bytes are bound to an authoritative digest or immutable source revision and have a measured SHA-256.",
        probable_exact: "Original distribution bytes, but no matching authoritative SHA-256 is available.",
        tree_equivalent: "Complete reconstructed file tree whose members are verified; original archive bytes are not established.",
      },
    },
    inventory: {
      attacks: new Set(inventory.attacks.map(x => x.attackDir)).size,
      version_targets: inventory.targets.length,
      remediation_targets: inventory.remediationTargets.length,
      by_ecosystem: Object.fromEntries(Object.entries(allEcosystems).sort()),
      reported_digests: hashCoverage(inventory),
    },
    corpus: corpusSummary(),
    version_target_coverage: {
      targets: globalCoverage.selected.length,
      acquired: globalCoverage.counts.acquired,
      comparator_only: globalCoverage.counts.comparator_only,
      unresolved: globalCoverage.counts.unresolved,
      timed_out: globalCoverage.counts.timed_out,
      pending: globalCoverage.counts.pending,
      by_ecosystem: globalCoverage.byEcosystem,
    },
    selected: {
      ecosystems: [...options.ecosystems].sort(),
      during_targets: coverage.selected.length,
      discovered_predecessors: predecessors.length,
      ...coverage.counts,
      by_ecosystem: coverage.byEcosystem,
      remediation: remediationCoverage(inventory, options.ecosystems),
    },
  };
  if (results.length) {
    report.last_run = Object.fromEntries([...new Set(results.map(x => x.status))].sort().map(status => [status, results.filter(x => x.status === status).length]));
  }
  fs.writeFileSync(options.report, yaml.dump(report, { noRefs: true, lineWidth: 100, sortKeys: false }));
  return report;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const inventory = loadInventory();
  let predecessors = [];
  if (options.before) predecessors = await addPredecessors(inventory.targets, options.ecosystems, options.beforeOnly);
  const during = options.hashOnly || options.beforeOnly || options.afterOnly
    ? []
    : inventory.targets.filter(x => options.ecosystems.has(x.ecosystem) && x.purl);
  const after = options.after && !options.beforeOnly && !options.hashOnly
    ? inventory.remediationTargets.filter(x => options.ecosystems.has(x.ecosystem) && x.purl)
    : [];
  let queue = options.hashOnly ? [...inventory.hashTargets] : [...during, ...after, ...predecessors];
  queue.sort((a, b) => a.attackDir.localeCompare(b.attackDir) || a.artifactId.localeCompare(b.artifactId) || (a.phase === "before" ? -1 : 1) || a.version.localeCompare(b.version));
  // Deduplicate repeated artifact declarations and any predecessor that is also affected elsewhere.
  queue = [...new Map(queue.map(x => [`${x.attackDir}\u0000${x.artifactId}\u0000${sampleKey(x)}`, x])).values()];
  if (options.fetch) {
    queue = queue.filter(target => {
      const state = manifestState(target);
      if (state.sample) return false;
      // A timeout left the target unanswered, so it is queued like a fresh one.
      return options.retry || !state.unresolved || state.unresolved.status === "timed_out";
    });
  }
  if (options.only) queue = queue.filter(x => x.attackDir.includes(options.only));
  if (options.liveOnly && !options.hashOnly) queue = await filterLiveTargets(queue);
  if (options.limit) queue = queue.slice(0, options.limit);

  let results = [];
  if (options.fetch) {
    if (!fs.existsSync(options.forager)) throw new Error(`Forager binary not found: ${options.forager}`);
    // A hash constraint needs its own invocation: Forager takes one digest per run and
    // falls back to an unconstrained PURL fetch when the digest does not resolve.
    const single = queue.filter(x => x.hashOnly || x.expectedDigest?.value || x.expectedSha256);
    const batched = queue.filter(x => !single.includes(x));
    const singleResults = await mapLimit(single, options.concurrency,
      (target, index) => fetchTarget(target, options, index + 1, queue.length));
    const groups = chunk(batched, options.batch);
    const batchResults = await mapLimit(groups, options.concurrency,
      (group, index) => fetchBatch(group, options, single.length + index * options.batch + 1, queue.length));
    results = [...singleResults, ...batchResults.flat()];
  }
  const report = writeReport(options, inventory, results, predecessors);
  process.stdout.write(yaml.dump({ queued: queue.length, predecessors: predecessors.length, coverage: report.selected, last_run: report.last_run || {} }, { noRefs: true, lineWidth: 100 }));
}

main().catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
