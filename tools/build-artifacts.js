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

/*
 * Ecosystems whose unit of distribution is a single archive. The distinction decides what
 * "complete" can mean: an AUR package is a set of files, so its PKGBUILD is the artifact,
 * while an npm release is one tarball, so a loose .js from inside it is a member and a
 * dropped .dll is not the package in any state.
 *
 * Thirteen samples were filed as complete releases when they were payloads or members --
 * a dropped sdd.dll standing in for the coa tarball, the build.js the attacker added to
 * eslint-scope. None of them produced a single comparison, so the corpus looked better
 * collected than it was and no benchmark was better for it.
 */
const ARCHIVE_ECOSYSTEMS = new Set(["npm", "pypi", "rubygems", "crates", "maven", "nuget",
  "packagist", "composer", "go", "hex", "cocoapods", "conda", "cpan"]);
const ARCHIVE_FORMS = new Set(["gzip", "zip", "bzip2", "xz", "zstd", "tar", "7z", "rar"]);

/*
 * fileForm is a cheap content form, used to keep a comparison honest. Two files are only
 * comparable when they are the same kind of thing: a differential detector handed a
 * package archive and a single loose source file will report the entire archive as new,
 * which is a finding about the pairing rather than about the attack.
 *
 * Magic wins over the suffix because recovery renames files -- a recovered archive is
 * often stored content-addressed as `.sample` -- and the bytes do not care. The suffix
 * stays as the fallback for source text, where a few header bytes identify nothing.
 */
const SIGNATURES = [
  [Buffer.from("1f8b", "hex"), "gzip"],
  [Buffer.from("fd377a585a00", "hex"), "xz"],
  [Buffer.from("425a68", "hex"), "bzip2"],
  [Buffer.from("28b52ffd", "hex"), "zstd"],
  [Buffer.from("504b0304", "hex"), "zip"],
  [Buffer.from("377abcaf271c", "hex"), "7z"],
  [Buffer.from("52617221 1a07".replace(/ /g, ""), "hex"), "rar"],
  [Buffer.from("7f454c46", "hex"), "elf"],
  [Buffer.from("4d5a", "hex"), "pe"],
];
const MACHO = new Set(["feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe"]);

function fileForm(body, name) {
  const head = body.subarray(0, 512);
  for (const [magic, form] of SIGNATURES) {
    if (head.subarray(0, magic.length).equals(magic)) return form;
  }
  if (head.length >= 262 && head.subarray(257, 262).toString("latin1") === "ustar") return "tar";
  if (MACHO.has(head.subarray(0, 4).toString("hex"))) return "macho";
  return path.extname(String(name)).toLowerCase() || "(none)";
}

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
function derivePairs(subject, phases, unmatched) {
  const sorted = phase => (phases[phase] || [])
    .slice()
    .sort((a, b) => compareVersions(a.version, b.version));
  const before = sorted("before");
  const during = sorted("during");
  const after = sorted("after");
  // classification travels with the side: `affected` or `carrier` is weaker evidence than
  // `malicious`, and a consumer judging a comparison needs to see that without the manifest.
  const ref = (phase, item) => ({
    subject, phase, version: item.version || null, file: item.name,
    classification: item.classification || null, sha256: item.sha256,
  });
  // Only like compares with like. Without this the corpus states comparisons such as a
  // plugin's single .php file against the plugin's zip, or a wheel against a dropped
  // .scr, and every consumer has to relearn the same guard.
  const comparable = (a, b) => a && b && a.form === b.form;
  const pairs = [];

  // The before closest below a compromised release is the honest comparator for it.
  for (const bad of during) {
    const like = before.filter(b => comparable(b, bad));
    const prior = like.filter(b => compareVersions(b.version, bad.version) < 0);
    const good = prior.length ? prior[prior.length - 1] : like[like.length - 1];
    if (good) {
      pairs.push({ kind: "attack", expect: "detect", old: ref("before", good), new: ref("during", bad) });
    } else if (unmatched && before.length) {
      /*
       * The corpus holds a clean release for this subject but cannot compare it: the
       * files are different kinds of thing, and a loose payload against a package archive
       * is not a comparison. Worth reporting, because unlike a missing `before` it is
       * usually fixable -- acquire the clean release in the form the compromised one is
       * held in, or extract the compromised member from its archive.
       *
       * A subject with no clean release at all is the corpus's ordinary coverage gap;
       * `tools/missing-samples.js` is where that is tracked, and repeating thousands of
       * them here would bury this.
       */
      unmatched.push(`${subject}@${bad.version || "unversioned"}: held as ${bad.form}, ` +
        `but the clean releases are ${[...new Set(before.map(b => b.form))].join(", ")}`);
    }
  }
  for (const bad of during) {
    const like = after.filter(a => comparable(a, bad));
    const fix = like.find(a => compareVersions(a.version, bad.version) > 0) || like[0];
    if (fix) pairs.push({ kind: "remediation", expect: "no-detect", old: ref("during", bad), new: ref("after", fix) });
  }
  if (before.length && after.length) {
    const newest = before[before.length - 1];
    const fixed = after.filter(a => comparable(a, newest)).pop();
    if (fixed) {
      pairs.push({ kind: "net", expect: "no-detect", old: ref("before", newest), new: ref("after", fixed) });
    }
  }
  // Adjacent clean releases are upgrades a real user performed; flagging one is a false
  // positive. Adjacent within one form: an sdist and a wheel of the same release are two
  // distributions of one version, not an upgrade from one to the next.
  const byForm = new Map();
  for (const item of before) {
    if (!byForm.has(item.form)) byForm.set(item.form, []);
    byForm.get(item.form).push(item);
  }
  for (const chain of byForm.values()) {
    for (let i = 1; i < chain.length; i += 1) {
      pairs.push({ kind: "baseline", expect: "no-detect",
        old: ref("before", chain[i - 1]), new: ref("before", chain[i]) });
    }
  }
  return pairs;
}

/*
 * Every path this run is responsible for, whether or not its bytes had to be rewritten.
 * The sweep at the end removes everything else, which is the only thing that makes the
 * tree a function of the records rather than an accumulation of every build that ever
 * ran: a record that loses a comparison, a sample that is renamed or re-phased, a record
 * that is deleted outright.
 */
const emitted = new Set();

function write(file, body, apply) {
  emitted.add(path.resolve(file));
  if (!apply) return;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
}

// sweep deletes what this run did not produce, and any directory left empty by that.
function sweep(dir, removed = { files: 0 }) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      sweep(file, removed);
      if (!fs.readdirSync(file).length) fs.rmdirSync(file);
    } else if (!emitted.has(path.resolve(file))) {
      fs.rmSync(file);
      removed.files += 1;
    }
  }
  return removed.files;
}

function main() {
  const options = parseArgs(process.argv);
  const stats = { records: 0, files: 0, complete: 0, parts: 0, missing: 0, collisions: 0, renamed: 0, pairs: 0 };
  const bySubject = [];
  const byDigest = new Map();
  const fidelity = [];
  const problems = [];
  const unmatched = [];
  const notArchives = [];
  const formsHeld = Object.create(null);

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
    const ecosystems = new Map();
    for (const item of doc) {
      for (const artifact of (item && item.artifacts) || []) {
        artifactLocations.set(artifact.id, artifact.locations || item.locations || []);
        ecosystems.set(artifact.id, String(artifact.ecosystem || "").toLowerCase());
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
        // Recorded either way: unchanged bytes are still this run's output.
        emitted.add(path.resolve(destination));
        if (needed) write(destination, body, options.apply);

        stats.files += 1;
        if (complete) stats.complete += 1; else stats.parts += 1;

        if (complete && ARCHIVE_ECOSYSTEMS.has(ecosystems.get(sample.artifact_id)) &&
            !ARCHIVE_FORMS.has(fileForm(body, name))) {
          notArchives.push({ recordId, subject, phase, name,
            form: fileForm(body, name), ecosystem: ecosystems.get(sample.artifact_id) });
        }
        (formsHeld[`${recordId}\u0000${subject}\u0000${phase}`] ||= new Set())
          .add(fileForm(body, name));

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
        // Evidence about the event rather than a release of this subject.
        if (String(sample.scope || "") === "incident") record.scope = "incident";
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
            name, version: release === UNVERSIONED ? null : release,
            classification: sample.classification || null,
            form: fileForm(body, name), sha256: digest });
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
    for (const [subject, phases] of completeBySubject) {
      pairs.push(...derivePairs(subject, phases, unmatched));
    }
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
  /*
   * A loose member is only a problem when nothing can be compared with it. Where another
   * phase of the same subject holds the same form -- rand-user-agent keeps the clean and
   * malicious index.js side by side -- the record is deliberately comparing members, which
   * is a sound differential test and often the only one the incident allows.
   */
  const stranded = notArchives.filter(item => !["before", "during", "after"]
    .some(phase => phase !== item.phase &&
      (formsHeld[`${item.recordId}\u0000${item.subject}\u0000${phase}`] || new Set()).has(item.form)));
  out.write(`${stats.records} records, ${stats.files} files ` +
    `(${stats.complete} complete, ${stats.parts} parts)\n`);
  out.write(`  renamed to mark a reassembly: ${stats.renamed}\n`);
  out.write(`  filename collisions resolved: ${stats.collisions}\n`);
  out.write(`  samples whose bytes are missing: ${stats.missing}\n`);
  out.write(`  distinct digests: ${byDigest.size}\n`);
  out.write(`  comparisons stated in pairs.yaml: ${stats.pairs}\n`);
  out.write(`  compromised releases whose clean side is a different form: ${unmatched.length}\n`);
  out.write(`  filed as a release, not an archive, nothing to compare: ${stranded.length}\n`);

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
    // Only a complete build knows what the whole tree should contain.
    const stale = options.only ? 0 : sweep(options.out);
    out.write(`\nwrote ${options.out}` +
      (options.only ? " (partial build; stale files left in place)\n"
                    : `, removed ${stale} stale file(s)\n`));
  } else {
    out.write(`\nreport only; pass --apply to write to ${options.out}\n`);
  }

  if (stranded.length) {
    out.write(`\n${stranded.length} sample(s) filed as a complete release that are neither the ` +
      `distribution form of their ecosystem nor comparable with another phase:\n`);
    for (const item of stranded.slice(0, 15)) {
      out.write(`  ${item.recordId}/${item.subject}/${item.phase}/${item.name}: ` +
        `${item.ecosystem} distributes archives and this is ${item.form}\n`);
    }
    if (stranded.length > 15) out.write(`  … ${stranded.length - 15} more\n`);
  }

  if (unmatched.length) {
    out.write(`\n${unmatched.length} compromised release(s) held in a form none of their ` +
      `clean releases share:\n`);
    for (const line of unmatched.slice(0, 20)) out.write(`  ${line}\n`);
    if (unmatched.length > 20) out.write(`  … ${unmatched.length - 20} more\n`);
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
