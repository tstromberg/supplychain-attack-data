#!/usr/bin/env node
"use strict";

/*
 * Writes reviewed pull quotes into the records they belong to.
 *
 *   node tools/apply-pull-quotes.js quotes.yaml [--dry-run]
 *
 * The input is what an audit produces, one entry per record:
 *
 *   - id: trivy-second-compromise
 *     text: >-
 *       Tags can point at commits pushed from forks, so moving v0.2.5 onto a
 *       fork commit was enough to serve malicious code to everyone pinned by tag.
 *     caption: why tag pinning failed
 *     after: 2
 *     source: https://www.stepsecurity.io/blog/trivy-compromised-a-second-time
 *
 * `source` stays in the audit file rather than the record: the record already
 * lists its references, and a quote drawn from one of them needs no second
 * pointer.
 *
 * Records are edited as text, not parsed and re-emitted. A round trip through a
 * YAML dumper would reformat every block scalar in the file and bury one added
 * field in hundreds of lines of churn.
 *
 * A record that already carries a quote is left alone, so an interrupted audit
 * can be re-run without trampling earlier review.
 */

const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..");
const CORPORA = ["oss", "proprietary"];

/*
 * A pull quote has to land in one look. Past these sizes it is a paragraph
 * wearing a rule on its left, and the reader skips it. The same limits are
 * enforced by the Go validator in cmd/yaml2csv; if you change one, change both.
 */
const MAX_WORDS = 40;
const MAX_SENTENCES = 2;
const MAX_CAPTION_WORDS = 8;

// Fold long text at a width that keeps the record readable without splitting a
// token across lines.
const FOLD_WIDTH = 78;

function findRecordFiles(dir, found = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "samples" || entry.name === "refs" || entry.name === "node_modules") continue;
      findRecordFiles(full, found);
    } else if (entry.name === "meta.yaml") {
      found.push(full);
    }
  }
  return found;
}


// Splits a record file into its sequence items, with each item's id and the
// offsets it spans. Items are found by the top-level "- " marker, and the id is
// read from whichever line inside declares it.
function splitRecords(source) {
  const starts = [];
  const marker = /^- /gm;
  let match;
  while ((match = marker.exec(source)) !== null) starts.push(match.index);

  return starts.map((start, index) => {
    const end = index + 1 < starts.length ? starts[index + 1] : source.length;
    const body = source.slice(start, end);
    // Matches "- id: x" on the first line and "  id: x" on any later one.
    const found = body.match(/^(?:- |  )id:[ \t]+(\S+)[ \t]*$/m);
    return { id: found ? found[1] : null, start, end, body };
  });
}

function words(value) {
  return String(value || "").trim().split(/\s+/).filter(Boolean);
}

// A period between two digits ends a version number, not a sentence, which is
// the same rule the Go validator applies.
function countSentences(value) {
  return (String(value).match(/[.!?](?=\s|$)/g) || []).length;
}

function foldText(text, indent) {
  const lines = [];
  let line = indent;
  for (const word of words(text)) {
    if (line.length > indent.length && line.length + word.length + 1 > FOLD_WIDTH) {
      lines.push(line);
      line = indent;
    }
    line += (line.length > indent.length ? " " : "") + word;
  }
  if (line.trim()) lines.push(line);
  return lines.join("\n");
}

function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const quotesFile = args.find(arg => !arg.startsWith("--"));
  if (!quotesFile || !fs.existsSync(quotesFile)) {
    console.error("usage: apply-pull-quotes.js quotes.yaml [--dry-run]");
    process.exit(2);
  }

  const entries = yaml.load(fs.readFileSync(quotesFile, "utf8"));
  if (!Array.isArray(entries)) {
    console.error("expected a YAML sequence of quote entries");
    process.exit(2);
  }

  // Record ids do not always match their directory names, so every file is read
  // once and indexed by the ids it actually declares. A record's id is usually
  // its first key but need not be — campaign files lead with title — so records
  // are split on the sequence marker and the id looked up inside each.
  const locations = new Map();
  for (const corpus of CORPORA) {
    const dir = path.join(ROOT, corpus);
    if (!fs.existsSync(dir)) continue;
    for (const file of findRecordFiles(dir)) {
      for (const { id } of splitRecords(fs.readFileSync(file, "utf8"))) {
        if (id) locations.set(id, file);
      }
    }
  }

  let applied = 0;
  let skipped = 0;
  let rejected = 0;

  for (const entry of entries) {
    const id = String(entry && entry.id || "").trim();
    const text = String(entry && entry.text || "").trim().replace(/\s+/g, " ");
    const caption = String(entry && entry.caption || "").trim();
    const fail = reason => {
      console.error(`${id || "(no id)"}: ${reason}`);
      rejected++;
    };

    if (!id) { fail("entry has no id"); continue; }
    if (!text) { fail("entry has no text"); continue; }

    const wordCount = words(text).length;
    const sentenceCount = countSentences(text);
    const captionWords = caption ? words(caption).length : 0;
    if (wordCount > MAX_WORDS) { fail(`${wordCount} words, limit is ${MAX_WORDS}`); continue; }
    if (sentenceCount > MAX_SENTENCES) { fail(`${sentenceCount} sentences, limit is ${MAX_SENTENCES}`); continue; }
    if (captionWords > MAX_CAPTION_WORDS) { fail(`caption is ${captionWords} words, limit is ${MAX_CAPTION_WORDS}`); continue; }

    const file = locations.get(id);
    if (!file) { fail("no record with this id"); continue; }

    const source = fs.readFileSync(file, "utf8");

    // Everything below is scoped to this record. A handful of files hold several
    // in one sequence, and anchoring on the file's first start_date would file
    // the quote under a neighbour.
    const found = splitRecords(source).find(entry => entry.id === id);
    if (!found) { fail(`not found in ${path.relative(ROOT, file)}`); continue; }
    const { start, body: record } = found;

    if (/^ {2}pull_quote:/m.test(record)) { skipped++; continue; }

    // Records are a YAML sequence of mappings indented two spaces. Anchoring on
    // start_date keeps the quote with the rest of the record header.
    const anchor = record.search(/^ {2}start_date:/m);
    if (anchor < 0) { fail("no start_date to anchor on"); continue; }

    let block = "  pull_quote:\n    text: >-\n" + foldText(text, "      ") + "\n";
    if (caption) block += `    caption: ${caption}\n`;
    if (entry.after !== undefined && entry.after !== null) block += `    after: ${entry.after}\n`;

    if (dryRun) {
      console.log(`${id}: would write to ${path.relative(ROOT, file)}`);
    } else {
      fs.writeFileSync(file, source.slice(0, start + anchor) + block + source.slice(start + anchor));
    }
    applied++;
  }

  console.log(`${dryRun ? "would apply" : "applied"} ${applied}, skipped ${skipped} already quoted, ${rejected} rejected`);
  if (rejected > 0) process.exit(1);
}

main();
