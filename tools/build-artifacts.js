#!/usr/bin/env node

/*
 * Generate the browsable artifact tree from the records.
 *
 *   <record-id>/<subject>/<phase>/<filename>          complete distributed artifacts
 *   <record-id>/<subject>/<phase>/parts/<filename>    components and fragments
 *   <record-id>/<subject>/<phase>/provenance.yaml     where each file came from
 *   <record-id>/README.md                             what the record is, and its evidence
 *
 * The tree is a projection. Nothing in it is authoritative except the bytes, and every
 * other file is derived from the manifests in git, so it can be deleted and rebuilt. That
 * is what keeps the two stores from drifting: a name or a phase cannot disagree with the
 * metadata, because the metadata is what produced it.
 *
 * Three things the layout encodes so that a consumer needs no parser:
 *
 *   - a file at the phase level is a complete artifact; anything partial is under parts/,
 *     so `before/*` against `during/*` is always a valid comparison
 *   - a reassembly is named `-RECONSTRUCTED`, derived from the metadata rather than
 *     trusted from the stored filename, which disagrees for 362 samples today
 *   - a phase directory holding only parts/ means no complete artifact was ever recovered
 *
 *   node tools/build-artifacts.js [--out DIR] [--apply] [--only SUBSTRING]
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
const DEFAULT_OUT = path.join(os.homedir(), "data", "supplychain-attack-data");

// Completeness is about whether the bytes are the whole artifact, not how they were
// obtained: a reassembled full tree is complete, a captured fragment is not.
const COMPLETE = new Set([
  "exact", "probable_exact", "tree_equivalent", "checksum_verified", "source_snapshot",
]);

// Kinds where the URL we fetched from is also the channel the attack was served through.
const WAS_DISTRIBUTION = new Set([
  "distribution", "official_registry", "official_distribution_endpoint",
  "distribution_mirror", "reconstructed_distribution", "clean_comparator_distribution",
]);

function parseArgs(argv) {
  const options = { out: DEFAULT_OUT, apply: false, only: "" };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--out") options.out = path.resolve(argv[++i]);
    else if (argv[i] === "--apply") options.apply = true;
    else if (argv[i] === "--only") options.only = String(argv[++i] || "").toLowerCase();
    else if (argv[i] === "--help" || argv[i] === "-h") {
      process.stderr.write("Usage: node tools/build-artifacts.js [--out DIR] [--apply] [--only SUBSTRING]\n");
      process.exit(0);
    }
  }
  return options;
}

function records() {
  const found = [];
  const walk = dir => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name === "refs" || entry.name === "samples") continue;
      const child = path.join(dir, entry.name);
      if (fs.existsSync(path.join(child, "meta.yaml")) &&
          fs.existsSync(path.join(child, "samples", "manifest.yaml"))) found.push(child);
      walk(child);
    }
  };
  for (const scope of SCOPES) walk(scope);
  return found;
}

function isReconstruction(sample) {
  const source = sample.source || {};
  return Boolean(source.reconstruction) || String(source.kind || "") === "reconstructed_distribution";
}

// displayName derives the filename from the metadata rather than trusting the stored one.
// A reassembly says so in its name; anything else keeps the name it was distributed under.
function displayName(sample) {
  let name = path.basename(String(sample.filename || sample.path || "artifact"));
  name = name.replace(/\.xz$/, "");
  if (!isReconstruction(sample)) return name;
  if (/RECONSTRUCT/i.test(name)) return name;
  const dot = name.indexOf(".");
  return dot > 0 ? `${name.slice(0, dot)}-RECONSTRUCTED${name.slice(dot)}` : `${name}-RECONSTRUCTED`;
}

/*
 * distributedFrom answers the question a researcher actually asks — where a victim would
 * have got this — which is not the same as where we later found a copy. The manifest
 * records the second for 99% of samples and the first for 15%, so it is resolved from the
 * best evidence available and left unknown rather than guessed.
 */
function distributedFrom(sample, artifactLocations) {
  const source = sample.source || {};
  if (source.original_url) return String(source.original_url);
  if (source.url && WAS_DISTRIBUTION.has(String(source.kind || ""))) return String(source.url);
  const declared = (artifactLocations.get(sample.artifact_id) || [])
    .find(location => String(location.role || "") === "distribution");
  return declared ? String(declared.uri) : "unknown";
}

/*
 * Where a sample sits under its phase. A release directory makes the version a first-class
 * part of the path rather than something a consumer parses back out of a filename -- which
 * is guesswork, since distributors write versions as they please (3.9p1-11.el4_7,
 * 2.0.13-848.v76e89de8a_053), and since some filenames carry no version at all: AccessPress
 * archives are named for the Wayback capture that recovered them.
 *
 * The name comes straight from the record, never re-derived here, so a researcher reading a
 * manifest can predict the path. `unversioned` is a real answer, not a fallback: a payload
 * recovered by digest from MalwareBazaar often has no knowable release, and several records
 * say so outright. Filing it under a guessed version would turn a documented gap into a
 * false claim.
 */
const UNVERSIONED = "unversioned";

function releasesOf(sample) {
  const { version, commit } = sample;
  // A list means the identical bytes shipped in each release, so the file belongs to all.
  if (Array.isArray(version) && version.length) return version.map(String);
  if (version) return [String(version)];
  if (commit) return [String(commit)];
  return [UNVERSIONED];
}

/*
 * originSegment names the subdirectory a record stores a sample under, when that
 * subdirectory is not simply the subject repeated. Two values occur across the corpus --
 * `base` and `inputs` -- and both say the same thing: this file is an input a
 * reconstruction was built from, not something that was ever distributed.
 *
 * Keeping it is what separates the 14-member Forager partial from the 16-member archive
 * built on top of it. Both are named <package>-<version>-RECONSTRUCTED-PARTIAL.tgz,
 * because that is what they are, and taking the basename alone collapsed them into one
 * slot. It accounts for every filename collision in the corpus.
 */
function originSegment(sample) {
  const extra = path.dirname(String(sample.path || "")).split("/").slice(2).join("/");
  if (!extra || extra === String(sample.subject || "")) return null;
  return extra;
}



// meta.yaml dates parse into Date objects, whose default rendering is a local-time string
// with a timezone name. Records are dated, not timestamped.
function isoDate(value) {
  if (!value) return "";
  if (value instanceof Date) return value.toISOString().slice(0, 10);
  return String(value).slice(0, 10);
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

/*
 * Version ordering, good enough to pick a comparator. Releases here are semver-ish but not
 * reliably semver -- some carry commit ids, some carry dates -- so numeric runs are
 * compared numerically and everything else lexically, and an unparseable version sorts
 * last rather than throwing.
 */
function compareVersions(a, b) {
  const split = v => String(v || "").split(/[.\-+_]/).filter(Boolean);
  const x = split(a);
  const y = split(b);
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
    const p = x[i];
    const q = y[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const np = /^\d+$/.test(p);
    const nq = /^\d+$/.test(q);
    if (np && nq) {
      if (Number(p) !== Number(q)) return Number(p) - Number(q);
    } else if (p !== q) {
      return p < q ? -1 : 1;
    }
  }
  return 0;
}

/*
 * derivePairs states the comparisons a differential tool should make, and what it should
 * conclude from each. Today that expectation lives in the consumer -- isomer reconstructs
 * it by preferring complete captures and guessing version affinity -- which means every
 * consumer reimplements the corpus's intent. Saying it here makes it reviewable.
 *
 * Only complete artifacts are paired: a fragment against a full archive is not a
 * comparison, it is a mistake.
 */
function derivePairs(subject, phases) {
  const sorted = phase => (phases[phase] || [])
    .slice()
    .sort((a, b) => compareVersions(a.version, b.version));
  const before = sorted("before");
  const during = sorted("during");
  const after = sorted("after");
  const ref = (phase, item) => ({
    subject, phase, version: item.version || null, file: item.name, sha256: item.sha256,
  });
  const pairs = [];

  // The before closest below a compromised release is the honest comparator for it.
  for (const bad of during) {
    const prior = before.filter(b => compareVersions(b.version, bad.version) < 0);
    const good = prior.length ? prior[prior.length - 1] : before[before.length - 1];
    if (good) pairs.push({ kind: "attack", expect: "detect", old: ref("before", good), new: ref("during", bad) });
  }
  for (const bad of during) {
    const fix = after.find(a => compareVersions(a.version, bad.version) > 0) || after[0];
    if (fix) pairs.push({ kind: "remediation", expect: "no-detect", old: ref("during", bad), new: ref("after", fix) });
  }
  if (before.length && after.length) {
    pairs.push({ kind: "net", expect: "no-detect",
      old: ref("before", before[before.length - 1]), new: ref("after", after[after.length - 1]) });
  }
  // Adjacent clean releases are upgrades a real user performed; flagging one is a false positive.
  for (let i = 1; i < before.length; i += 1) {
    pairs.push({ kind: "baseline", expect: "no-detect",
      old: ref("before", before[i - 1]), new: ref("before", before[i]) });
  }
  return pairs;
}

function write(file, body, apply) {
  if (!apply) return;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
}

function main() {
  const options = parseArgs(process.argv);
  const stats = { records: 0, files: 0, complete: 0, parts: 0, missing: 0, collisions: 0, renamed: 0, pairs: 0 };
  const bySubject = [];
  const byDigest = new Map();
  const fidelity = [];
  const problems = [];

  for (const dir of records()) {
    const recordDir = path.relative(ROOT, dir);
    if (options.only && !recordDir.toLowerCase().includes(options.only)) continue;
    const doc = yaml.load(fs.readFileSync(path.join(dir, "meta.yaml"), "utf8")) || [];
    const manifest = yaml.load(fs.readFileSync(path.join(dir, "samples", "manifest.yaml"), "utf8")) || {};
    const samples = manifest.samples || [];
    if (!samples.length) continue;

    const entry = doc.find(item => item && item.artifacts) || doc[0] || {};
    const recordId = String(entry.id || path.basename(dir));
    const artifactLocations = new Map();
    for (const item of doc) {
      for (const artifact of (item && item.artifacts) || []) {
        artifactLocations.set(artifact.id, artifact.locations || item.locations || []);
      }
    }

    stats.records += 1;
    const groups = new Map();   // subject\0phase -> entries
    for (const sample of samples) {
      const subject = String(sample.subject || sample.artifact_id || "unknown");
      const phase = String(sample.phase || "unknown");
      const stored = path.join(dir, "samples", String(sample.path || ""));
      if (!fs.existsSync(stored)) {
        stats.missing += 1;
        problems.push(`${recordId}: bytes missing for ${sample.filename}`);
        continue;
      }
      for (const release of releasesOf(sample)) {
        const key = `${subject}\u0000${phase}\u0000${release}`;
        if (!groups.has(key)) groups.set(key, { subject, phase, release, entries: [] });
        groups.get(key).entries.push({ sample, stored });
      }
    }

    const readmeRows = [];
    const completeBySubject = new Map();   // subject -> { before: [], during: [], after: [] }
    for (const { subject, phase, release, entries } of groups.values()) {
      const base = path.join(options.out, recordId, subject, phase, release);
      const used = new Map();
      const provenance = [];

      for (const { sample, stored } of entries) {
        const status = String((sample.verification || {}).status || "");
        const complete = COMPLETE.has(status);
        let name = displayName(sample);
        if (name !== path.basename(String(sample.filename || ""))) stats.renamed += 1;

        // A collision is a defect, not a layout problem. Disambiguate so the build
        // completes, and report it so the underlying record gets fixed.
        // A complete artifact always sits at the release level, whatever the record filed
        // it under, because `<release>/*` has to stay a valid comparison input. Only a
        // fragment keeps the record's own subdirectory.
        const origin = complete ? null : originSegment(sample);
        const prefix = `${complete ? "" : "parts/"}${origin ? `${origin}/` : ""}`;
        const slot = `${prefix}${name}`;
        if (used.has(slot) && used.get(slot) !== sample.sha256) {
          stats.collisions += 1;
          problems.push(`${recordId}/${subject}/${phase}: two samples want ${name}`);
          const dot = name.indexOf(".");
          const tag = String(sample.sha256 || "").slice(0, 12);
          name = dot > 0 ? `${name.slice(0, dot)}-${tag}${name.slice(dot)}` : `${name}-${tag}`;
        }
        used.set(slot, sample.sha256);

        const destination = path.join(base, ...prefix.split("/").filter(Boolean), name);
        const body = fs.readFileSync(stored);
        const digest = sha256(body);
        if (sample.sha256 && digest !== sample.sha256) {
          problems.push(`${recordId}: ${name} hashes ${digest.slice(0, 12)}, manifest says ${String(sample.sha256).slice(0, 12)}`);
          continue;
        }

        // Incremental: only write when the destination differs.
        let needed = true;
        if (fs.existsSync(destination) && fs.statSync(destination).size === body.length) {
          needed = sha256(fs.readFileSync(destination)) !== digest;
        }
        if (needed) write(destination, body, options.apply);

        stats.files += 1;
        if (complete) stats.complete += 1; else stats.parts += 1;

        const relative = path.join(recordId, subject, phase, release, `${prefix}${name}`);
        if (!byDigest.has(digest)) byDigest.set(digest, relative);
        fidelity.push([relative, status || "unknown",
          ((sample.verification || {}).basis || []).join("+") || "-",
          isReconstruction(sample) ? "reconstructed" : "captured"].join("\t"));

        const source = sample.source || {};
        const record = {
          file: name,
          sha256: digest,
          size: body.length,
          fidelity: status || "unknown",
          basis: (sample.verification || {}).basis || [],
          evidence: (sample.verification || {}).evidence || [],
          distributed_from: distributedFrom(sample, artifactLocations),
          recovered_from: source.url || "unknown",
          recovered_via: source.kind || "unknown",
        };
        // The release is the directory this sidecar sits in; the header states it once.
        if (sample.commit) record.commit = String(sample.commit);
        if (source.retrieved_at) record.recovered_at = String(source.retrieved_at);
        if ((sample.notes || []).length) record.notes = sample.notes;
        if (source.reconstruction) record.reconstruction = source.reconstruction;
        provenance.push(record);
        readmeRows.push({ subject, phase, release, name, status, complete, prefix,
                          distributed: distributedFrom(sample, artifactLocations) });
        if (complete) {
          if (!completeBySubject.has(subject)) completeBySubject.set(subject, {});
          const slots = completeBySubject.get(subject);
          (slots[phase] ||= []).push({
            name, version: release === UNVERSIONED ? null : release, sha256: digest });
        }
      }

      if (provenance.length) {
        write(path.join(base, "provenance.yaml"),
          yaml.dump({ record: recordId, subject, phase, release, files: provenance },
            { noRefs: true, lineWidth: 100, sortKeys: false }), options.apply);
      }
      bySubject.push(`${subject}\t${recordId}`);
    }

    const pairs = [];
    for (const [subject, phases] of completeBySubject) pairs.push(...derivePairs(subject, phases));
    if (pairs.length) {
      stats.pairs += pairs.length;
      write(path.join(options.out, recordId, "pairs.yaml"),
        yaml.dump({ record: recordId, pairs }, { noRefs: true, lineWidth: 100, sortKeys: false }),
        options.apply);
    }
    if (readmeRows.length) write(path.join(options.out, recordId, "README.md"),
      renderReadme(entry, recordId, readmeRows), options.apply);
  }

  const out = process.stdout;
  out.write(`${stats.records} records, ${stats.files} files ` +
    `(${stats.complete} complete, ${stats.parts} parts)\n`);
  out.write(`  renamed to mark a reassembly: ${stats.renamed}\n`);
  out.write(`  filename collisions resolved: ${stats.collisions}\n`);
  out.write(`  samples whose bytes are missing: ${stats.missing}\n`);
  out.write(`  distinct digests: ${byDigest.size}\n`);
  out.write(`  comparisons stated in pairs.yaml: ${stats.pairs}\n`);

  if (options.apply) {
    write(path.join(options.out, "by-subject.tsv"), `${[...new Set(bySubject)].sort().join("\n")}\n`, true);
    write(path.join(options.out, "by-digest.tsv"),
      `${[...byDigest].map(([d, p]) => `${d}\t${p}`).sort().join("\n")}\n`, true);
    write(path.join(options.out, "fidelity.tsv"), `${fidelity.sort().join("\n")}\n`, true);
    let commit = "unknown";
    try { commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT }).toString().trim(); } catch {}
    write(path.join(options.out, "BUILD.yaml"), yaml.dump({
      built_from: commit, built_at: new Date().toISOString(),
      tool: "tools/build-artifacts.js", records: stats.records, files: stats.files,
    }, { noRefs: true, sortKeys: false }), true);
    out.write(`\nwrote ${options.out}\n`);
  } else {
    out.write(`\nreport only; pass --apply to write to ${options.out}\n`);
  }

  if (problems.length) {
    out.write(`\n${problems.length} problem(s):\n`);
    for (const line of problems.slice(0, 25)) out.write(`  ${line}\n`);
    if (problems.length > 25) out.write(`  … ${problems.length - 25} more\n`);
  }
}

function renderReadme(entry, recordId, rows) {
  const lines = [`# ${entry.title || recordId}`, ""];
  if (entry.synopsis) lines.push(String(entry.synopsis).trim(), "");
  const from = isoDate(entry.start_date);
  const to = isoDate(entry.end_date);
  const when = from && to && from !== to ? `${from} to ${to}` : (from || to);
  if (when) lines.push(`**When:** ${when}`, "");
  lines.push("| subject | phase | release | file | fidelity | distributed from |",
             "|---|---|---|---|---|---|");
  for (const r of rows.slice(0, 200)) {
    lines.push(`| ${r.subject} | ${r.phase} | ${r.release} | ` +
      `${r.complete ? "" : "parts/"}${r.name} | ${r.status} | ${r.distributed} |`);
  }
  if (rows.length > 200) lines.push(`| … | | | ${rows.length - 200} more files | | |`);
  lines.push("", "Generated by `tools/build-artifacts.js`. The bytes are authoritative;",
    "every other file here is derived from the record in git and can be rebuilt.", "");
  return lines.join("\n");
}

try {
  main();
} catch (error) {
  process.stderr.write(`build-artifacts: ${error.stack || error.message}\n`);
  process.exitCode = 1;
}
