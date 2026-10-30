#!/usr/bin/env node

/*
 * Binds held npm samples to the digest the registry published for them.
 *
 * A sample's fidelity is a claim about what is known, and for most npm samples the
 * corpus could only claim the weaker thing: probable_exact for bytes from a mirror,
 * tree_equivalent for an archive re-packed from a CDN's file listing. npm's own
 * dist.integrity and dist.shasum settle it, and Backstabber's Knife Collection keeps
 * that metadata beside every release it holds.
 *
 * So this asks one question per sample: do the bytes we hold reproduce the digest npm
 * published? A yes makes the sample exact, whatever lane it came from. A no is the more
 * interesting answer — it means a re-packing is not the published archive, which is
 * exactly what "reconstructed" is supposed to mean, and the entry keeps saying so.
 *
 *   node tools/bind-registry-digests.js --corpus /path/to/corpus/npm [--dry-run]
 *
 * Only the metadata is needed, not the archives, so the corpus copy can be a tree of
 * meta.json.zst files alone.
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const yaml = require("js-yaml");
const { verificationFrom } = require("./normalize-basis.js");
const provenance = require("./provenance-store.js");

const ROOT = path.resolve(__dirname, "..");
const SCOPES = [path.join(ROOT, "oss", "attacks"), path.join(ROOT, "proprietary")];

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/bind-registry-digests.js --corpus DIR [options]\n\n` +
    `  --corpus DIR   Corpus npm tree holding <package>/<version>/meta.json.zst\n` +
    `  --only SUB     Restrict to incidents whose directory matches\n` +
    `  --dry-run      Report the verdicts and stop\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = {};
  for (let i = 2; i < argv.length; i += 1) {
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) usage(1);
      i += 1;
      return next;
    };
    const arg = argv[i];
    if (arg === "--corpus") options.corpus = path.resolve(value());
    else if (arg === "--only") options.only = value().toLowerCase();
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--help" || arg === "-h") usage(0);
    else usage(1);
  }
  if (!options.corpus) usage(1);
  return options;
}

function manifests(dir, found = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isDirectory()) continue;
    const child = path.join(dir, entry.name);
    if (entry.name === "samples") {
      const file = path.join(child, "manifest.yaml");
      if (fs.existsSync(file)) found.push(file);
      continue;
    }
    if (entry.name === "refs") continue;
    manifests(child, found);
  }
  return found;
}

function registryDist(corpus, name, version) {
  const file = path.join(corpus, name, version, "meta.json.zst");
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(execFileSync("zstd", ["-dc", file], { maxBuffer: 64 * 1024 * 1024 }).toString()).dist || null;
  } catch (_) {
    return null;
  }
}

/*
 * match reports whether body is the archive npm published. dist.integrity is a base64
 * digest prefixed by its algorithm and dist.shasum the SHA-1; either one binding the
 * bytes is decisive, and a sample with neither is left exactly as it was.
 */
function match(body, dist) {
  const basis = [];
  if (dist.integrity) {
    const [algorithm, expected] = String(dist.integrity).split("-", 2);
    if (algorithm && expected) {
      if (crypto.createHash(algorithm).update(body).digest("base64") !== expected) return null;
      basis.push(`registry_${algorithm}_integrity`);
    }
  }
  if (dist.shasum) {
    if (crypto.createHash("sha1").update(body).digest("hex") !== String(dist.shasum)) return null;
    basis.push("registry_shasum");
  }
  return basis.length ? basis : null;
}

function main() {
  const options = parseArgs(process.argv);
  let bound = 0;
  let differs = 0;
  let unknown = 0;
  let already = 0;

  for (const scope of SCOPES) {
    for (const manifestFile of manifests(scope)) {
      if (options.only && !manifestFile.toLowerCase().includes(options.only)) continue;
      const samplesDir = path.dirname(manifestFile);
      const manifest = yaml.load(fs.readFileSync(manifestFile, "utf8")) || {};
      let touched = false;

      for (const sample of manifest.samples || []) {
        const coordinate = String(sample.coordinate || "");
        if (!coordinate.startsWith("pkg:npm/")) continue;
        const at = coordinate.lastIndexOf("@");
        if (at < 0) continue;
        const name = decodeURIComponent(coordinate.slice("pkg:npm/".length, at));
        const version = decodeURIComponent(coordinate.slice(at + 1));
        const dist = registryDist(options.corpus, name, version);
        if (!dist) {
          unknown += 1;
          continue;
        }
        const file = path.join(samplesDir, String(sample.path || ""));
        if (!fs.existsSync(file)) {
          unknown += 1;
          continue;
        }
        const basis = match(fs.readFileSync(file), dist);
        if (!basis) {
          differs += 1;
          process.stdout.write(`differs   ${name}@${version} (${sample.verification?.status})\n`);
          continue;
        }
        if (sample.verification?.status === "exact") {
          already += 1;
          continue;
        }
        bound += 1;
        process.stdout.write(`bound     ${name}@${version} (${sample.verification?.status} -> exact)\n`);
        if (options.dryRun) continue;
        // A file still named RECONSTRUCTED cannot be exact, and the verifier says so.
        // The name was the claim that these bytes were rebuilt; the registry digest has
        // just disproved it, so the name goes with the status.
        if (/-RECONSTRUCTED\./.test(sample.filename)) {
          const plain = sample.filename.replace(/-RECONSTRUCTED(\.[^.]+(?:\.[^.]+)?)$/, "$1");
          const from = path.join(samplesDir, sample.path);
          const to = path.join(path.dirname(from), plain);
          if (fs.existsSync(from)) {
            fs.chmodSync(from, 0o644);
            fs.renameSync(from, to);
            fs.chmodSync(to, 0o444);
          }
          sample.filename = plain;
          sample.path = path.join(path.dirname(sample.path), plain);
          /*
           * The reconstruction claim in the acquisition record is now false -- the
           * registry digest proved these are the published bytes -- so it comes out of
           * every acquisition of them. The provenance document itself does not move: it is
           * filed under a digest the rename did not change.
           */
          const document = provenance.read(samplesDir, sample.sha256);
          if (document) {
            for (const acquisition of document.acquisitions || []) {
              if (acquisition.artifact) acquisition.artifact.filename = plain;
              if (acquisition.provenance) delete acquisition.provenance.reconstruction;
            }
            provenance.write(samplesDir, document);
          }
          if (sample.source) {
            delete sample.source.reconstruction;
            sample.source.kind = "distribution";
          }
        }
        /*
         * Evidence carries forward, minus the claims the registry digest has just
         * superseded: where the copy came from stops mattering once the bytes reproduce
         * the digest the registry itself published. The basis terms are derived from what
         * is left, so they cannot drift from the vocabulary the verifier enforces.
         */
        const carried = (sample.verification?.evidence || sample.verification?.basis || [])
          .filter(x => !/^(distribution_mirror_retained_published_tarball|research_corpus_retained_archive)$/.test(x));
        sample.verification = verificationFrom("exact", [...new Set([...basis, ...carried])]);
        sample.notes = [
          "Bound to the registry's own digest on 2026-09-10: these bytes reproduce the dist.integrity " +
          "npm published for this version, which settles that they are the archive the registry served " +
          "rather than a copy that merely claims the coordinate.",
          ...(sample.notes || []).filter(x => !/^Synthetic archive:/i.test(String(x))),
        ];
        touched = true;
      }

      if (touched && !options.dryRun) {
        fs.writeFileSync(manifestFile, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
      }
    }
  }

  process.stderr.write(`\n${bound} bound to a registry digest, ${differs} differ from it, ` +
    `${already} already exact, ${unknown} with no metadata in the corpus\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
}
