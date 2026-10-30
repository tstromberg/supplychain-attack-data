#!/usr/bin/env node

/*
 * Turn `verification.basis` into a controlled vocabulary.
 *
 * `basis` is meant to answer one question -- why should a reader believe these bytes are
 * what the record claims? -- and it is the corpus's only machine-readable statement of
 * evidence. It had stopped being one. 33,602 uses spread across 1,413 distinct values, 937
 * of them used exactly once, in strings like
 *
 *   retained_jsdelivr_manifest_accounts_for_all_1280_members
 *   npm_dist_SHA1_match_dc57c10d7607b2931b59454cd572724509b822c9
 *   wayback_cdx_digest_FYUTZZUHPKWIECDHWVUNWPE7AAHLTUJD
 *
 * Those are sentences with the spaces removed. Nothing can group by them, so no one can
 * ask how much of the corpus rests on a publisher's own digest versus on a report's
 * say-so -- which is the first question anyone auditing a malware corpus should ask.
 *
 * The particulars are still evidence, though: the digest, the member count and the
 * indicator filename are the substance. So this is a lossless split rather than a
 * replacement.
 *
 *   verification.basis      the controlled term(s)  -- what kind of evidence this is
 *   verification.evidence   the original strings    -- the particulars, verbatim
 *
 * Anything the classifier cannot place keeps its original string in `evidence` and
 * contributes no term, so an unrecognized value degrades to "unexplained" rather than
 * being silently dropped or forced into the nearest bucket.
 *
 *   node tools/normalize-basis.js            report only
 *   node tools/normalize-basis.js --apply    rewrite the manifests
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];

/*
 * The vocabulary. Each term names a kind of evidence, and the comment says what a reader
 * is entitled to conclude from it -- which is the part that matters, because the terms are
 * how the corpus will be queried.
 *
 * Order is significant: the first matching rule wins, so the specific sits above the
 * general. `npm_dist_SHA1_match_<hex>` has to be read as a publisher digest before the
 * bare word "sha1" can make it look like something we measured ourselves.
 */
const RULES = [
  // `\b` is useless here: underscore is a word character, so \bnpm never matches inside
  // dist_npm_sha. Segments are anchored with (?:^|_) instead.
  //
  // The publisher or registry stated a digest and these bytes reproduce it. The strongest
  // evidence short of the original transfer: it binds the bytes to the distributor's own
  // record rather than to anyone's later report.
  [/(?:^|_)(dist_?(integrity|sha)|registry_(sha|shasum|integrity|published)|npm_(dist|registry|sha)|rubygems_api|crates_io_index|modrinth_\w*api|authoritative_npm|jsdelivr|independently_published|published_(digest|checksum))/i,
    "publisher_digest_reproduced"],

  // A version-control object id. Content-addressed by construction.
  [/(?:^|_)(git_blob|git_object|git_parent|immutable_(git|svn)|blob_id|hopper_content_address)/i,
    "git_object_id_verified"],

  // An indicator that a compromised copy would carry is absent.
  [/(?:^|_)(no_[A-Za-z0-9]+_(in|or)|not_blacklisted|clean_of|absence_of|zero_missing|reports_no_detections|does_not_match|mismatch_confirms)/i,
    "indicator_absent"],

  // A digest published in a report, advisory, bulletin or IOC table matches. Depends on the
  // reporter having been right, which is why it is not the same claim as the one above.
  [/(?:^|_)(reported|advisory|triage_reported|requested_sha|original_reporter|campaign|embedded_telemetry|same_cluster|corroborat|contemporary)/i,
    "reported_digest_matched"],

  // Every member of a reconstructed archive matches a recorded digest.
  [/(?:^|_)(all_\d*|every|zero)_?\w*(members?|paths)\w*(match|sha256|digest)|members_match|stored_q_members_match|byte_identical_to_the_published|complete_retained_file_tree|content_addresses_decode/i,
    "all_members_digest_matched"],

  // A third-party file listing (Socket, jsDelivr) retained as the record of what the
  // release contained. Evidence about the target, not about the bytes in hand.
  [/(?:^|_)(retained|reconstructed)_\w*(socket|jsdelivr|member|manifest)|(socket|member)_\w*listing|content_id/i,
    "member_manifest_retained"],

  // Members were missing and were recovered by looking them up by digest.
  [/(?:^|_)\w*members_resolved_by_digest|resolved_by_digest_and_re_measured/i, "members_resolved_by_digest"],

  // The reconstruction is incomplete and the record says so.
  [/(?:^|_)(partial_reconstruction|partial_capture|partial_base|forager_partial)/i, "some_members_unresolved"],

  // The reconstruction's method, inputs and overlays are recorded in the manifest.
  [/(?:^|_)(reconstruction|overlay|stitched|forager_member_reconstruction|reconstructed_archived)/i,
    "reconstruction_documented"],

  // The evidence is another sample held in this same record.
  [/(?:^|_)(in_this_manifest|held_in_this|extracted_from_the_official_release_archive|exact_local_case|research_corpus|existing_\w+_payload_bytes|retained_(member|archive))/i,
    "derived_from_sample_in_this_record"],

  // Fetched from the vendor's, registry's or marketplace's own endpoint.
  [/(?:^|_)(official|registry_(tarball|download|distribution)|distribution_endpoint|downloaded_from_the_vendor|vendor_distribution)/i,
    "official_distribution_endpoint"],

  // A mirror that retained the artifact after the origin removed it.
  [/(?:^|_)mirror/i, "distribution_mirror"],

  // Served back by a web or source archive.
  [/(?:^|_)(wayback|web_archive|archived_(replay|copy|source)|software_heritage)/i, "web_archive_replay"],

  // Held by a malware repository under its own custody record.
  [/(?:^|_)(malwarebazaar|triage|malshare|virustotal|abuse_ch|hopper|forager)(?:_|$)/i,
    "malware_repository_custody"],

  // Two independent preservations hold the same bytes.
  [/(?:^|_)(independent|two_independent|byte_identical_in_two)/i, "independent_preservation_agreement"],

  // The archive's own metadata states the version or identity it claims.
  [/(?:^|_)(archive_declares|internal_package_json|declares_(version|its_own_version)|embedded_name_and_version|vsixmanifest_identity)/i,
    "archive_declares_version"],

  // Named as the release that removed the compromise.
  [/(?:^|_)(first_fixed|first_stable|backdoor_removed|post_remediation|remediat)/i,
    "remediation_release_identified"],

  // A known malicious indicator is present in the bytes.
  [/(?:^|_)(payload_(file|indicator)|sabotage|malicious|backdoor_present|hidden_unicode|obfuscat|exfil|loader_present|install_js)/i,
    "payload_indicator_present"],

  // Text reproduced from a report's own rendering of the code, rather than recovered bytes.
  [/(?:^|_)(transcribed|report_(code|excerpt)|published_(screenshot|code_block)|exact_report)/i,
    "transcribed_from_report"],

  // The container is the file type it claims to be.
  [/(?:^|_)(elf|macho|mach_o|pe|zip|gzip|tar|vsix_zip)_\w*(header|signature)|file_format|magic_bytes|parses_as_valid/i,
    "file_format_confirmed"],

  // The coordinate -- package name and version -- is exactly the affected one, or an
  // advisory names that version as compromised.
  [/(?:^|_)(exact_package_name_and_version|exact_purl|package_name_and_version|coordinate|advisory_identifies_version)/i,
    "coordinate_matches"],

  // We hashed the retained bytes ourselves. Says the file has not changed since we stored
  // it; says nothing on its own about whether it is the right file.
  [/(?:^|_)measured_|_and_measured$|_and_size$|(?:^|_)sha256$/i, "measured_sha256"],
];

// The vocabulary itself, for consumers that need to check a value rather than assign one.
const TERMS = new Set(RULES.map(([, term]) => term));

/*
 * verificationFrom builds a verification block from the particulars an acquisition tool
 * already knows. The tool keeps saying what it actually established -- `registry_shasum`,
 * `wayback_original_replay` -- and the terms are derived, so a new acquisition cannot
 * introduce a vocabulary value by hand and cannot drift out of step with the validator.
 */
function verificationFrom(status, evidence) {
  const basis = [];
  for (const item of evidence) {
    const term = classify(String(item));
    if (term && !basis.includes(term)) basis.push(term);
  }
  return { status, basis, evidence: evidence.map(String) };
}

function classify(value) {
  // Already a term: a second run must not reclassify its own output.
  if (TERMS.has(value)) return value;
  for (const [pattern, term] of RULES) {
    if (pattern.test(value)) return term;
  }
  return null;
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
  const termUses = new Map();
  const unplaced = new Map();
  let uses = 0;
  let placed = 0;
  let samples = 0;
  const emptied = [];
  const touched = [];

  for (const file of manifests()) {
    const manifest = yaml.load(fs.readFileSync(file, "utf8")) || {};
    let dirty = false;

    for (const sample of manifest.samples || []) {
      const verification = sample.verification;
      if (!verification || !Array.isArray(verification.basis)) continue;
      /*
       * `evidence` holds the particulars and is written once. On a re-run it, not `basis`,
       * is the input -- otherwise a second pass would replace the original strings with the
       * terms derived from them and the particulars would be gone for good.
       */
      const original = (Array.isArray(verification.evidence) && verification.evidence.length
        ? verification.evidence : verification.basis).map(String);
      if (!original.length) continue;
      samples += 1;

      const terms = [];
      for (const value of original) {
        uses += 1;
        const term = classify(value);
        if (!term) {
          unplaced.set(value, (unplaced.get(value) || 0) + 1);
          continue;
        }
        placed += 1;
        termUses.set(term, (termUses.get(term) || 0) + 1);
        if (!terms.includes(term)) terms.push(term);
      }

      if (!terms.length) {
        emptied.push(`${sample.subject}/${sample.phase}/${sample.filename}: ${original.join(", ")}`);
      }
      if (apply) {
        verification.basis = terms;
        verification.evidence = original;
      }
      dirty = true;
    }

    if (dirty && apply) {
      fs.writeFileSync(file, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
      touched.push(path.relative(ROOT, file));
    }
  }

  const out = process.stdout;
  out.write(`${uses} basis uses; ${placed} placed (${(100 * placed / uses).toFixed(1)}%), ` +
    `${uses - placed} unplaced across ${unplaced.size} distinct values\n\n`);
  out.write(`${termUses.size} terms in use:\n`);
  for (const [term, n] of [...termUses].sort((a, b) => b[1] - a[1])) {
    out.write(`  ${String(n).padStart(6)}  ${term}\n`);
  }

  out.write(`\n${samples} samples carried a basis; ${emptied.length} would be left with none\n`);
  for (const item of emptied.slice(0, 15)) out.write(`  ${item}\n`);
  if (emptied.length > 15) out.write(`  … ${emptied.length - 15} more\n`);

  if (unplaced.size) {
    out.write(`\nunplaced, most common first:\n`);
    for (const [value, n] of [...unplaced].sort((a, b) => b[1] - a[1]).slice(0, 40)) {
      out.write(`  ${String(n).padStart(5)}  ${value}\n`);
    }
  }
  out.write(apply ? `\nwrote ${touched.length} manifest(s)\n` : `\nreport only; pass --apply to write\n`);
}

module.exports = { TERMS, classify, verificationFrom };

if (require.main === module) try {
  main();
} catch (error) {
  process.stderr.write(`normalize-basis: ${error.stack || error.message}\n`);
  process.exitCode = 1;
}
