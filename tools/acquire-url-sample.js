#!/usr/bin/env node

/*
 * Stores an artifact fetched from a URL, bound to a digest the record already names.
 *
 * Some distribution points never stop serving the release that carried the attack.
 * Jenkins keeps every plugin version it has ever published, WordPress keeps closed
 * plugins' tagged archives, and a vendor download path often outlives the incident
 * that ran through it. Where that is true the malicious bytes are still available
 * from the channel that delivered them, which is the strongest provenance a sample
 * can have -- better than a research collection, because it is the distribution
 * itself rather than someone's copy of it.
 *
 * The digest is not optional. A URL says where bytes came from and nothing about
 * which bytes they are, and an update site asked for a withdrawn version may answer
 * with the current one instead. So the caller states the SHA-256 the record already
 * carries, and a fetch that does not reproduce it is refused rather than stored.
 *
 *   node tools/acquire-url-sample.js --incident checkmarx-may-2026 \
 *     --artifact checkmarx-ast-scanner --version 2026.5.09 \
 *     --url https://updates.jenkins.io/download/plugins/... \
 *     --expect 01ff1e56...9203
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
  process.stderr.write(`Usage: node tools/acquire-url-sample.js --incident ID --artifact ID ` +
    `--url URL --expect SHA256 [options]\n\n` +
    `  --phase PHASE      during (default), before or after\n` +
    `  --version VERSION  Version the artifact was published as\n` +
    `  --coordinate PURL  Package coordinate to record\n` +
    `  --filename NAME    Stored filename (default: the URL's last path segment)\n` +
    `  --kind KIND        source.kind (default: distribution)\n` +
    `  --file PATH        Store these already-fetched bytes instead of fetching --url,\n` +
    `                     for a source that needs credentials curl is not given\n` +
    `  --status STATUS    verification.status (default: exact)\n` +
    `  --basis NAME       an evidence particular, repeatable; the basis term is derived\n` +
    `  --note TEXT        Note for the manifest entry, repeatable\n` +
    `  --dry-run          Fetch, report the digest and stop\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = { phase: "during", kind: "distribution", notes: [], basis: [], status: "exact" };
  for (let i = 2; i < argv.length; i += 1) {
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) usage(1);
      i += 1;
      return next;
    };
    const arg = argv[i];
    if (arg === "--incident") options.incident = value();
    else if (arg === "--artifact") options.artifact = value();
    else if (arg === "--url") options.url = value();
    else if (arg === "--expect") options.expect = value().toLowerCase();
    else if (arg === "--phase") options.phase = value();
    else if (arg === "--version") options.version = value();
    else if (arg === "--coordinate") options.coordinate = value();
    else if (arg === "--filename") options.filename = value();
    else if (arg === "--kind") options.kind = value();
    else if (arg === "--note") options.notes.push(value());
    else if (arg === "--file") options.file = value();
    else if (arg === "--status") options.status = value();
    else if (arg === "--basis") options.basis.push(value());
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--help" || arg === "-h") usage(0);
    else usage(1);
  }
  if (!options.incident || !options.artifact || !options.url) usage(1);
  if (!/^[0-9a-f]{64}$/.test(options.expect || "")) usage(1);
  return options;
}

function attackDir(incident) {
  for (const scope of SCOPES) {
    for (const entry of fs.readdirSync(scope, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const base = path.join(scope, entry.name);
      for (const dir of [base, ...fs.readdirSync(base, { withFileTypes: true })
        .filter(child => child.isDirectory())
        .map(child => path.join(base, child.name))]) {
        const meta = path.join(dir, "meta.yaml");
        if (!fs.existsSync(meta)) continue;
        if (fs.readFileSync(meta, "utf8").includes(`- id: ${incident}\n`)) return dir;
      }
    }
  }
  throw new Error(`no record names the incident ${incident}`);
}

function loadManifest(file) {
  if (!fs.existsSync(file)) return { schema_version: 1, samples: [], unresolved: [] };
  const value = yaml.load(fs.readFileSync(file, "utf8")) || {};
  value.samples ||= [];
  value.unresolved ||= [];
  return value;
}

async function main() {
  const options = parseArgs(process.argv);
  const dir = attackDir(options.incident);
  const name = options.filename || path.basename(new URL(options.url).pathname) || "artifact";

  const temporary = path.join(require("node:os").tmpdir(), `acquire-${process.pid}-${name}`);
  if (options.file) fs.copyFileSync(options.file, temporary);
  else execFileSync("curl", ["-sSL", "--max-time", "900", "-o", temporary, options.url], { stdio: ["ignore", "ignore", "inherit"] });
  const body = fs.readFileSync(temporary);
  const digest = crypto.createHash("sha256").update(body).digest("hex");
  process.stderr.write(`fetched ${name}: ${body.length} bytes sha256:${digest}\n`);
  if (digest !== options.expect) {
    fs.unlinkSync(temporary);
    throw new Error(`digest mismatch: expected ${options.expect}, got ${digest}`);
  }
  if (options.dryRun) {
    fs.unlinkSync(temporary);
    return;
  }

  const destinationDir = path.join(dir, "samples", options.artifact, options.phase);
  fs.mkdirSync(destinationDir, { recursive: true });
  const destination = path.join(destinationDir, name);
  if (fs.existsSync(destination)) fs.chmodSync(destination, 0o644);
  fs.renameSync(temporary, destination);

  // Large samples are kept compressed, and one too large even then stays out of git.
  fs.chmodSync(destination, 0o444);

  const retrievedAt = new Date().toISOString();
  provenance.record(path.join(dir, "samples"), digest, body.length, {
    schema_version: "1.0",
    artifact: { filename: name, sha256: digest, size_bytes: body.length },
    fetch: { collector: "url-sample-recovery", category: options.kind, at: retrievedAt, url: options.url },
  });

  const entry = {
    artifact_id: options.artifact,
    phase: options.phase,
    classification: options.phase === "during" ? "malicious" : "clean",
    ...(options.coordinate ? { coordinate: options.coordinate } : {}),
    ...(options.version ? { version: options.version } : {}),
    filename: name,
    path: path.relative(path.join(dir, "samples"), destination),
    sha256: digest,
    size: body.length,
    source: { url: options.url, retrieved_at: retrievedAt, kind: options.kind },
    verification: verificationFrom(options.status,
      options.basis.length ? options.basis : ["reported_sha256", "measured_sha256"]),
    ...(options.notes.length ? { notes: options.notes } : {}),
  };

  const manifestFile = path.join(dir, "samples", "manifest.yaml");
  const manifest = loadManifest(manifestFile);
  const key = item => [item.artifact_id, item.phase, item.filename].join(" ");
  manifest.samples = manifest.samples.filter(item => key(item) !== key(entry));
  manifest.samples.push(entry);
  fs.writeFileSync(manifestFile, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
  process.stderr.write(`stored ${path.relative(ROOT, destination)}\n`);
}

main().catch(error => {
  process.stderr.write(`acquire-url-sample: ${error.message}\n`);
  process.exitCode = 1;
});
