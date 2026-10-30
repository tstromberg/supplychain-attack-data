#!/usr/bin/env node

// Reports which attacks still lack a sample for one collection phase.
//
// The unit of collection is an artifact, not an attack: an attack is only fully
// covered when every artifact its record names has a sample of the phase. Coverage
// is read from samples/manifest.yaml, which is the maintained record of what has
// been acquired, and falls back to the on-disk layout for artifacts a manifest has
// not caught up with yet.
//
//   node tools/missing-samples.js --phase during [--out MUST-FIND.md]

const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");

const root = path.resolve(__dirname, "..");
const scopes = [path.join(root, "oss", "attacks"), path.join(root, "proprietary")];
const phases = ["before", "during", "after"];

// An "after" sample can only exist once a remediated release does, so artifacts
// with no fixed version are excluded from that phase rather than counted missing.
//
// Some artifacts have no "during" state to collect either, and no amount of searching
// will produce one: the poisoning happened at runtime and no release was ever
// malicious, or the tampered files were never publicly named. A record says so with
// during_sample_not_expected, whose value is the reason. That is stated in the record
// rather than inferred here, so a genuinely missing sample is never quietly hidden.
function expected(artifact, phase) {
  if (phase === "during" && artifact.during_sample_not_expected) return false;
  if (phase !== "after") return true;
  return (artifact.fixed_versions || []).length > 0;
}

function readYaml(file) {
  try {
    return yaml.load(fs.readFileSync(file, "utf8"));
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw new Error(`${file}: ${err.message}`);
  }
}

/*
 * A metadata_backed_evidence_record is a stub generated from the incident's own
 * meta.yaml, and it says so: "This is not a recovered payload." It occupies a sample
 * slot so an operator can see the gap, and it must never answer the question of whether
 * that gap is filled. The closed-source lane once reported 163 of 163 artifacts acquired
 * on the strength of 117 of these; see "A placeholder is not an acquisition" in
 * SAMPLE_ACQUISITION.md. The same trap is why this is checked here and not only in the
 * acquisition tools: a report that counts stubs is a report that hides its own work.
 */
function isPlaceholder(sample) {
  return String(sample.source?.kind || "") === "metadata_backed_evidence_record" ||
    String(sample.filename || "").endsWith("-evidence.fragment");
}

// Artifact ids covered for each phase, by manifest entry or by stored bytes.
function coverage(samplesDir) {
  const covered = new Map(phases.map((phase) => [phase, new Set()]));
  const manifest = readYaml(path.join(samplesDir, "manifest.yaml"));
  const stubs = new Set();
  for (const sample of manifest?.samples || []) {
    if (!covered.has(sample.phase) || !sample.artifact_id) continue;
    if (isPlaceholder(sample)) {
      stubs.add(`${sample.phase}\u0000${sample.artifact_id}`);
      continue;
    }
    covered.get(sample.phase).add(sample.artifact_id);
  }
  if (!fs.existsSync(samplesDir)) return covered;
  // The on-disk fallback catches artifacts a manifest has not caught up with, but a
  // directory holding nothing but a stub is not coverage either.
  for (const artifact of fs.readdirSync(samplesDir, { withFileTypes: true })) {
    if (!artifact.isDirectory()) continue;
    for (const phase of phases) {
      const dir = path.join(samplesDir, artifact.name, phase);
      if (!fs.existsSync(dir)) continue;
      const real = fs.readdirSync(dir).filter((name) => !name.endsWith("-evidence.fragment") &&
        !name.endsWith("-evidence.fragment.forage.json"));
      if (real.length > 0) covered.get(phase).add(artifact.name);
    }
  }
  for (const key of stubs) {
    const [phase, artifactId] = key.split("\u0000");
    if (!covered.get(phase).has(artifactId)) covered.get(phase).delete(artifactId);
  }
  return covered;
}

// One entry per attack record. A directory may hold several records that share a
// samples directory, so coverage is read once per directory and matched by artifact id.
function survey(phase) {
  const attacks = [];
  for (const scope of scopes) {
    for (const entry of fs.readdirSync(scope, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isDirectory()) continue;
      const attackDir = path.join(scope, entry.name);
      const records = readYaml(path.join(attackDir, "meta.yaml"));
      if (!records) continue;
      const covered = coverage(path.join(attackDir, "samples")).get(phase);
      for (const record of records) {
        const artifacts = (record.artifacts || []).filter((artifact) => expected(artifact, phase));
        const missing = artifacts.filter((artifact) => !covered.has(artifact.id));
        const excused = phase === "during"
          ? (record.artifacts || []).filter((artifact) => artifact.during_sample_not_expected)
          : [];
        attacks.push({
          id: record.id,
          title: record.title || record.id,
          ecosystems: [...new Set(artifacts.map((artifact) => artifact.ecosystem).filter(Boolean))].sort(),
          artifacts: artifacts.length,
          missing: missing.map((artifact) => artifact.id || artifact.name),
          excused: excused.map((artifact) => ({
            id: artifact.id || artifact.name,
            reason: String(artifact.during_sample_not_expected).trim(),
          })),
        });
      }
    }
  }
  return attacks;
}

function line(attack) {
  const where = attack.ecosystems.length ? ` — ${attack.ecosystems.join(", ")}` : "";
  return `- **${attack.title}** (\`${attack.id}\`)${where}`;
}

function report(phase, attacks) {
  const none = attacks.filter((a) => a.artifacts > 0 && a.missing.length === a.artifacts);
  const partial = attacks.filter((a) => a.missing.length > 0 && a.missing.length < a.artifacts);
  const empty = attacks.filter((a) => a.artifacts === 0);
  const covered = attacks.length - none.length - partial.length - empty.length;
  const out = [];

  out.push(`# Attacks missing \`${phase}\` samples`);
  out.push("");
  out.push(`Generated by \`make missing-${phase}\` on ${new Date().toISOString().slice(0, 10)}.`);
  out.push("");
  out.push(
    `Of ${attacks.length} attack records, ${covered} have ${phase === "after" ? "an" : "a"} \`${phase}\` sample for every artifact, ` +
      `${partial.length} have one for some, and ${none.length} have none.` +
      (empty.length > 0 ? ` ${empty.length} name no artifact for which this phase applies.` : ""),
  );
  out.push("");

  for (const [heading, group] of [
    [`No \`${phase}\` sample at all (${none.length})`, none],
    [`Partially covered (${partial.length})`, partial],
  ]) {
    out.push(`## ${heading}`);
    out.push("");
    if (group.length === 0) out.push("None.");
    for (const attack of group) {
      out.push(line(attack));
      if (group === partial) out.push(`  - missing ${attack.missing.length}/${attack.artifacts}: ${attack.missing.join(", ")}`);
    }
    out.push("");
  }

  const excused = attacks.filter((a) => a.excused?.length);
  if (excused.length > 0) {
    const count = excused.reduce((total, attack) => total + attack.excused.length, 0);
    out.push(`## No \`during\` sample to collect (${count})`);
    out.push("");
    out.push("These artifacts have no affected release to acquire, for the reason each record states.");
    out.push("");
    for (const attack of excused) {
      out.push(line(attack));
      for (const artifact of attack.excused) out.push(`  - ${artifact.id}: ${artifact.reason}`);
    }
    out.push("");
  }

  // An artifact only has an "after" state once the vendor shipped a fix, and most
  // records name none, so that exclusion is summarised above rather than enumerated.
  if (empty.length > 0 && phase !== "after") {
    out.push(`## No artifacts recorded (${empty.length})`);
    out.push("");
    out.push("These records name no artifact to collect, so no sample is expected until one is described.");
    out.push("");
    for (const attack of empty) out.push(line(attack));
    out.push("");
  }
  return out.join("\n");
}

function main(argv) {
  let phase = null;
  let out = null;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--phase") phase = argv[i + 1];
    else if (argv[i] === "--out") out = argv[i + 1];
    else throw new Error(`unknown argument: ${argv[i]}`);
    i += 1;
  }
  if (!phases.includes(phase)) throw new Error(`--phase must be one of ${phases.join(", ")}`);

  const text = `${report(phase, survey(phase))}\n`;
  if (!out) {
    process.stdout.write(text);
    return;
  }
  fs.writeFileSync(path.resolve(root, out), text);
  process.stderr.write(`wrote ${out}\n`);
}

try {
  main(process.argv.slice(2));
} catch (err) {
  process.stderr.write(`missing-samples: ${err.message}\n`);
  process.exitCode = 1;
}
