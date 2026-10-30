#!/usr/bin/env node

/*
 * Give every sample an explicit release identity: the thing a version directory is named for.
 *
 * The artifact tree files a sample under the release it belongs to, so that identity has to
 * be stated in the record rather than re-derived at build time -- otherwise a researcher
 * reading a manifest cannot predict the path the sample will land on. Two fields carry it:
 *
 *   version   the version string as the distributor wrote it
 *   commit    the source commit, where that is the release identity (AUR, git-served trees)
 *
 * The evidence is already in the records; it is just filed in the wrong place. A version
 * sits in the filename with the field left empty, a commit sits in `source.url`, and 43
 * samples put a role label -- `trojanized-installer`, `clean-library-comparator` -- in the
 * version field, where it restates the classification or the phase and identifies nothing.
 *
 * Guessing is bounded deliberately. A version read out of a filename is accepted only when
 * the rest of the filename names the subject and the candidate carries a dot, because the
 * failure mode is silent: `bash-uploader-line-525.fragment` yields "525", which would file
 * a Codecov fragment under a release that never existed. An explicit field is trusted as
 * written; a guess has to earn it.
 *
 * What is left over is left alone. A payload recovered by digest from MalwareBazaar often
 * has no knowable release -- several records say so outright -- and inventing one would
 * turn an honest gap into a false claim.
 *
 *   node tools/backfill-versions.js            report only
 *   node tools/backfill-versions.js --apply    write the fields
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];

const COMMIT = /^[0-9a-f]{7,40}$/;
const COMMIT_IN_TEXT = /\b[0-9a-f]{40}\b/;

// A version starts with a digit, after an optional v, and carries no space or comma. The
// pattern has to admit what distributors actually publish: 3.9p1-11.el4_7 (RPM),
// 2.0.13-848.v76e89de8a_053 (Jenkins), 0.0.0-6f9ba3f (npm prerelease).
const VERSION = /^v?\d[0-9A-Za-z._+~-]*$/;

const ARCHIVE = /\.(tar\.gz|tar\.bz2|tar\.xz|tgz|tbz|zip|gem|whl|jar|crate|nupkg|vsix|rpm|deb|exe|msi|dmg|pkg|apk|phar)$/i;

function isVersion(value) {
  return VERSION.test(value) && !COMMIT.test(value);
}

// A scalar naming several releases: "1.0.110,2.0.83,2.0.84" or "4.1.1 - 4.1.2". The same
// bytes shipped in each, so the sample belongs to all of them and the field becomes a list.
function splitVersions(raw) {
  const parts = raw.split(/\s*[,/]\s*|\s+-\s+/).map(p => p.trim()).filter(Boolean);
  if (parts.length < 2) return null;
  return parts.every(isVersion) ? parts : null;
}

const fold = value => String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");

/*
 * versionFromFilename reads a version out of a distributed filename. The subject has to
 * account for the rest of the name -- ctx-0.1.2-1.tar.gz against subject `ctx` -- so that a
 * trailing number in an unrelated name is not mistaken for a release.
 */
function versionFromFilename(subject, filename) {
  let name = path.basename(String(filename || "")).replace(/\.xz$/, "");
  if (!ARCHIVE.test(name)) return null;
  name = name.replace(/\.src\.rpm$/i, "").replace(ARCHIVE, "");

  const match = name.match(/^(.*?)[-_]v?(\d[0-9A-Za-z._+~]*(?:-[0-9A-Za-z._+~]+)*)$/);
  if (!match) return null;
  const [, stem, candidate] = match;
  if (!candidate.includes(".")) return null; // a dotless guess is too easy to get wrong
  if (!isVersion(candidate)) return null;

  const a = fold(stem);
  const b = fold(subject);
  if (!a || !b || !(a.includes(b) || b.includes(a))) return null;
  return candidate;
}

/*
 * versionFromSubject recovers a version that was slugified into the subject itself. A
 * number of artifact ids were minted from a release filename, so the version survives with
 * its dots turned into dashes: jdownloader2setup-windows-amd64-v11-0-30-exe is 11.0.30 and
 * orion-platform-2020-2-rc1 is 2020.2-rc1.
 *
 * Two or more dash-separated numbers are required. A single trailing number is how records
 * count variants -- noxplayer-malicious-update-variant-1 -- and reading that as a version
 * would invent three releases of NoxPlayer that never shipped.
 */
function versionFromSubject(subject) {
  const name = String(subject || "");
  const match = name.match(/-v?(\d+(?:-\d+){1,3})(?:-(rc\d+|hf\d+|beta\d+))?(?:-(?:exe|zip|msi|dmg|sh|bin))?$/i);
  if (!match) return null;
  const version = match[1].replace(/-/g, ".") + (match[2] ? `-${match[2].toLowerCase()}` : "");
  return isVersion(version) ? version : null;
}

function commitFrom(sample) {
  const source = sample.source || {};
  for (const text of [source.url, source.original_url]) {
    const match = String(text || "").match(COMMIT_IN_TEXT);
    if (match) return match[0];
  }
  const match = (sample.notes || []).join(" ").match(COMMIT_IN_TEXT);
  return match ? match[0] : null;
}

function manifests() {
  const found = [];
  const walk = dir => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name === "refs") continue;
      const child = path.join(dir, entry.name);
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
  let samples = 0;
  const counts = { kept: 0, split: 0, moved: 0, cleared: 0, filename: 0, subject: 0, commit: 0, none: 0 };
  const shown = { split: [], cleared: [], filename: [], subject: [], none: [] };
  const touched = [];

  for (const file of manifests()) {
    const record = path.relative(ROOT, path.dirname(path.dirname(file)));
    const manifest = yaml.load(fs.readFileSync(file, "utf8")) || {};
    let dirty = false;

    for (const sample of manifest.samples || []) {
      samples += 1;
      const where = `${record} ${sample.subject}/${sample.phase}/${sample.filename}`;
      const raw = sample.version == null ? null : String(sample.version);
      let version = null;
      let commit = null;

      if (raw && isVersion(raw)) {
        counts.kept += 1;
        continue;
      } else if (raw && COMMIT.test(raw)) {
        commit = raw;
        counts.moved += 1;
      } else if (raw && splitVersions(raw)) {
        version = splitVersions(raw);
        counts.split += 1;
        shown.split.push(`${where}  ${raw} -> [${version.join(", ")}]`);
      } else {
        /*
         * Whatever is in the field identifies nothing, so it comes out -- but it is not
         * discarded. `chain-2-october-2025` says which Notepad++ infection chain a payload
         * belongs to, which is real knowledge that simply was not a version; it moves to
         * the notes rather than being deleted along with the field.
         */
        if (raw) {
          counts.cleared += 1;
          shown.cleared.push(`${where}  drop version: ${raw}`);
          const kept = `Recorded under the non-version version label "${raw}" before release ` +
            "identities were normalized; the label is retained here because it is not derivable " +
            "from the version or commit.";
          if (apply) (sample.notes ||= []).push(kept);
        }
        version = versionFromFilename(sample.subject, sample.filename);
        if (version) {
          counts.filename += 1;
          shown.filename.push(`${where}  -> ${version}`);
        } else if ((commit = sample.commit ? String(sample.commit) : commitFrom(sample))) {
          // A commit outranks the subject slug: it is evidence, where a slug is a reading of
          // a name. xerox-phaser-6000-6010 is a printer model, and the AUR commit says so.
          counts.commit += 1;
        } else if ((version = versionFromSubject(sample.subject))) {
          counts.subject += 1;
          shown.subject.push(`${where}  -> ${version}`);
        } else {
          counts.none += 1;
          shown.none.push(`${where}  [${(sample.verification || {}).status || "?"}]`);
        }
      }

      const had = JSON.stringify([sample.version ?? null, sample.commit ?? null]);
      const wants = JSON.stringify([version ?? null, commit ?? null]);
      if (had === wants) continue;
      if (apply) {
        if (version) sample.version = version; else delete sample.version;
        if (commit) sample.commit = commit; else delete sample.commit;
      }
      dirty = true;
    }

    if (dirty && apply) {
      fs.writeFileSync(file, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
      touched.push(path.relative(ROOT, file));
    }
  }

  const out = process.stdout;
  // Counted per sample, not summed over the buckets: dropping a label and then finding an
  // identity are two things that happen to the same sample.
  out.write(`${samples} samples\n`);
  out.write(`  version kept as written        ${counts.kept}\n`);
  out.write(`  version split into a list      ${counts.split}\n`);
  out.write(`  commit moved out of version:   ${counts.moved}\n`);
  out.write(`  version read from the filename ${counts.filename}\n`);
  out.write(`  version read from the subject  ${counts.subject}\n`);
  out.write(`  commit read from url or notes  ${counts.commit}\n`);
  out.write(`  non-version label dropped      ${counts.cleared}\n`);
  out.write(`  no release identity            ${counts.none}\n`);

  for (const [label, list] of [["split", shown.split], ["dropped", shown.cleared],
                               ["from filename", shown.filename], ["from subject", shown.subject]]) {
    if (!list.length) continue;
    out.write(`\n-- ${label} (${list.length})\n`);
    for (const item of list.slice(0, 40)) out.write(`  ${item}\n`);
    if (list.length > 40) out.write(`  … ${list.length - 40} more\n`);
  }

  const byStatus = new Map();
  for (const item of shown.none) {
    const status = item.slice(item.lastIndexOf("[") + 1, -1);
    byStatus.set(status, (byStatus.get(status) || 0) + 1);
  }
  out.write(`\n-- no release identity (${shown.none.length}), by verification.status\n`);
  for (const [status, n] of [...byStatus].sort((a, b) => b[1] - a[1])) {
    out.write(`  ${n}\t${status}\n`);
  }

  out.write(apply ? `\nwrote ${touched.length} manifest(s)\n` : `\nreport only; pass --apply to write\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`backfill-versions: ${error.stack || error.message}\n`);
  process.exitCode = 1;
}
