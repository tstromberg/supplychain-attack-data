#!/usr/bin/env node

/*
 * Rebuild a removed npm release from its predecessor plus the members that changed.
 *
 * When a malicious version is unpublished the tarball goes, but two things usually
 * survive: jsDelivr keeps the file listing with a SHA-256 for every member, and the
 * version before it is still on the registry. Most members are byte-identical across
 * the two, so the only files that need finding are the handful the attacker touched —
 * and those are exactly the ones a research corpus is likely to already hold, because
 * they are what got reported.
 *
 * So the reconstruction is: take the predecessor's tree, keep every member whose hash
 * matches the manifest, and resolve the rest by hash from Hopper. Every member is
 * checked against jsDelivr's recorded digest, so a finished archive is one where all
 * members are individually verified even though the archive's own digest is not
 * knowable — npm never published one. That is what tree_equivalent means here.
 *
 * The tar is written deterministically (sorted paths, fixed mtime and ownership) so the
 * same inputs always produce the same bytes, and the result is reproducible.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const zlib = require("node:zlib");

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/reconstruct-npm-release.js --package NAME --version V --predecessor V [options]\n\n` +
    `  --package NAME       npm package, e.g. @cap-js/postgres\n` +
    `  --version V          The removed version to rebuild\n` +
    `  --predecessor V      The published version to build on\n` +
    `  --base-tarball PATH  Build on a local partial archive instead of a registry predecessor\n` +
    `  --hopper URL         Hopper base URL for resolving changed members by hash\n` +
    `  --out PATH           Write the tarball here\n` +
    `  --dry-run            Report what each member would come from and stop\n` +
    `  --no-swh             Do not fall back to Software Heritage\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = { hopper: "http://10.9.8.10:8081" };
  for (let i = 2; i < argv.length; i += 1) {
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) usage(1);
      i += 1;
      return next;
    };
    const arg = argv[i];
    if (arg === "--package") options.pkg = value();
    else if (arg === "--version") options.version = value();
    else if (arg === "--predecessor") options.predecessor = value();
    else if (arg === "--base-tarball") options.baseTarball = path.resolve(value());
    else if (arg === "--hopper") options.hopper = value().replace(/\/$/, "");
    else if (arg === "--out") options.out = path.resolve(value());
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--no-swh") options.noSwh = true;
    else if (arg === "--help") usage(0);
    else usage(1);
  }
  if (!options.pkg || !options.version || (!options.predecessor && !options.baseTarball)) usage(1);
  return options;
}

const sha256 = buf => crypto.createHash("sha256").update(buf).digest("hex");

function hopperToken() {
  if (process.env.HOPPER_TOKEN) return process.env.HOPPER_TOKEN.trim();
  try {
    return fs.readFileSync(path.join(os.homedir(), ".tok", "hopper"), "utf8").trim();
  } catch (_) {
    return "";
  }
}

// jsDelivr nests directories; flatten to "lib/foo.js" style paths with the SHA-256
// its manifest records, which it publishes base64 encoded.
function flatten(files, prefix = "") {
  const out = [];
  for (const f of files) {
    if (f.type === "directory") out.push(...flatten(f.files || [], `${prefix}${f.name}/`));
    else out.push({ name: `${prefix}${f.name}`, sha256: Buffer.from(f.hash, "base64").toString("hex"), size: f.size });
  }
  return out;
}

async function fetchBuffer(url, headers = {}) {
  const r = await fetch(url, { headers });
  if (!r.ok) return null;
  return Buffer.from(await r.arrayBuffer());
}


// A minimal deterministic ustar writer. Every field that could carry host state --
// mtime, uid, gid, uname, gname -- is pinned, and entries are emitted in sorted
// order, so the archive is a function of its members alone.
function tarball_(entries) {
  const blocks = [];
  for (const e of [...entries].sort((a, b) => a.name.localeCompare(b.name))) {
    const header = Buffer.alloc(512);
    const put = (text, offset, length) => header.write(String(text).slice(0, length - 1), offset, "utf8");
    const octal = (n, width) => n.toString(8).padStart(width - 1, "0") + "\0";
    // ustar splits a long path across name and prefix at a slash: up to 155 bytes
    // of leading directories go in prefix, the remainder in name. Without this a
    // perfectly ordinary npm path like dist/cjs/rules/<long>/<long>.cjs cannot be
    // written at all.
    let nameField = e.name; let prefixField = "";
    if (Buffer.byteLength(nameField) > 100) {
      const cut = nameField.lastIndexOf("/", nameField.length - 1);
      let split = -1;
      for (let i = 0; i < nameField.length; i += 1) {
        if (nameField[i] !== "/") continue;
        const head = nameField.slice(0, i); const tail = nameField.slice(i + 1);
        if (Buffer.byteLength(head) <= 155 && Buffer.byteLength(tail) <= 100) split = i;
      }
      if (split < 0) throw new Error(`path too long for ustar: ${e.name}`);
      prefixField = nameField.slice(0, split); nameField = nameField.slice(split + 1);
    }
    put(nameField, 0, 100);
    put(octal(0o644, 8), 100, 8);
    put(octal(0, 8), 108, 8);
    put(octal(0, 8), 116, 8);
    put(octal(e.body.length, 12), 124, 12);
    put(octal(0, 12), 136, 12);
    header.write("        ", 148, 8, "utf8");
    header.write("0", 156, 1, "utf8");
    header.write("ustar\0", 257, 6, "binary");
    header.write("00", 263, 2, "utf8");
    if (prefixField) header.write(prefixField, 345, 155, "utf8");
    let sum = 0;
    for (const b of header) sum += b;
    header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "utf8");
    blocks.push(header, e.body, Buffer.alloc((512 - (e.body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

async function main() {
  const options = parseArgs(process.argv);
  const enc = encodeURIComponent(options.pkg);
  const manifestUrl = `https://data.jsdelivr.com/v1/package/npm/${options.pkg}@${options.version}`;
  const manifest = await fetch(manifestUrl).then(r => (r.ok ? r.json() : null));
  if (!manifest) throw new Error(`jsDelivr has no manifest for ${options.pkg}@${options.version}`);
  const members = flatten(manifest.files).sort((a, b) => a.name.localeCompare(b.name));
  process.stdout.write(`${members.length} members recorded by jsDelivr for ${options.pkg}@${options.version}\n`);

  // The base is either the published predecessor, which is the usual case, or a
  // partial archive already in the corpus. A partial is the better base when every
  // version of the package was removed, because then no predecessor exists to fetch.
  const short = options.pkg.replace(/^@[^/]+\//, "");
  let tarball; let baseLabel;
  if (options.baseTarball) {
    tarball = fs.readFileSync(options.baseTarball);
    baseLabel = options.baseTarball;
  } else {
    const tarUrl = `https://registry.npmjs.org/${enc}/-/${short}-${options.predecessor}.tgz`;
    tarball = await fetchBuffer(tarUrl);
    if (!tarball) throw new Error(`registry has no ${options.pkg}@${options.predecessor}`);
    baseLabel = tarUrl;
  }
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "npmrecon-"));
  const baseDir = path.join(work, "base");
  fs.mkdirSync(baseDir);
  fs.writeFileSync(path.join(work, "pred.tgz"), tarball);
  execFileSync("tar", ["xzf", path.join(work, "pred.tgz"), "-C", baseDir]);
  process.stdout.write(`base: ${baseLabel}\n`);

  const token = hopperToken();
  const stage = path.join(work, "package");
  fs.mkdirSync(stage);
  const provenance = [];
  for (const m of members) {
    const fromBase = path.join(baseDir, "package", m.name);
    let bytes = null; let origin = null;
    if (fs.existsSync(fromBase)) {
      const candidate = fs.readFileSync(fromBase);
      if (sha256(candidate) === m.sha256) { bytes = candidate; origin = options.baseTarball ? "base archive" : `predecessor ${options.predecessor}`; }
    }
    if (!bytes) {
      const got = await fetchBuffer(`${options.hopper}/api/file/${m.sha256}`,
        token ? { Authorization: `Bearer ${token}` } : {});
      // Hopper answers 200 with a short error body for digests it cannot serve, so
      // the measured digest is the only acceptable proof.
      if (got && sha256(got) === m.sha256) { bytes = got; origin = "hopper"; }
    }
    // Software Heritage indexes source trees the malware store does not hold. It is
    // rate limited to about 120 requests an hour, so it is asked only for members
    // nothing closer could supply, and the sleep is part of the normal path.
    if (!bytes && !options.noSwh) {
      for (let attempt = 0; attempt < 6 && !bytes; attempt += 1) {
        let r = null;
        try {
          r = await fetch(`https://archive.softwareheritage.org/api/1/content/sha256:${m.sha256}/raw/`);
        } catch (_) { await new Promise(s => setTimeout(s, 5000)); continue; }
        if (r.status === 429 || Number(r.headers.get("x-ratelimit-remaining") || "1") <= 0) {
          const reset = Number(r.headers.get("x-ratelimit-reset") || "0") * 1000;
          const wait = Math.max(60000, reset - Date.now() + 5000);
          process.stdout.write(`  software heritage rate limited; waiting ${Math.round(wait / 1000)}s\n`);
          await new Promise(s => setTimeout(s, wait));
          continue;
        }
        if (!r.ok) break;
        const got = Buffer.from(await r.arrayBuffer());
        if (sha256(got) === m.sha256) { bytes = got; origin = "software-heritage"; }
        break;
      }
    }
    if (!bytes) {
      process.stdout.write(`  MISSING ${m.name}  ${m.sha256}\n`);
      provenance.push({ path: m.name, sha256: m.sha256, source: null });
      continue;
    }
    const dest = path.join(stage, m.name);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, bytes);
    provenance.push({ path: m.name, sha256: m.sha256, source: origin });
    process.stdout.write(`  ${String(origin).padEnd(18)}  ${m.name}\n`);
  }
  const missing = provenance.filter(p => !p.source);
  process.stdout.write(`\nresolved ${provenance.length - missing.length}/${provenance.length} members` +
    `${missing.length ? `; ${missing.length} missing` : ""}\n`);
  if (missing.length || options.dryRun || !options.out) {
    fs.writeFileSync(path.join(work, "provenance.json"), JSON.stringify(provenance, null, 1));
    process.stdout.write(`work dir: ${work}\n`);
    return;
  }
  // The tar is written here rather than shelled out to, because the platform tars
  // disagree about the flags that make output reproducible: BSD tar has no --mtime
  // and no --files-from in the GNU spelling. Writing ustar headers directly fixes
  // every field that would otherwise vary, so the same inputs give the same bytes.
  if (fs.existsSync(options.out)) throw new Error(`refusing to overwrite ${options.out}`);
  const buf = tarball_(provenance.map(p => ({ name: `package/${p.path}`, body: fs.readFileSync(path.join(stage, p.path)) })));
  fs.writeFileSync(options.out, zlib.gzipSync(buf, { level: 9, mtime: 0 }));
  const out = fs.readFileSync(options.out);
  process.stdout.write(`wrote ${options.out}\n  sha256 ${sha256(out)}  ${out.length} bytes\n`);
  fs.writeFileSync(`${options.out}.provenance.json`, `${JSON.stringify(provenance, null, 1)}\n`);
}

main().catch(e => { process.stderr.write(`${e.message}\n`); process.exit(1); });
