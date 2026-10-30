#!/usr/bin/env node

/*
 * List and download the contents of a public MEGA folder link.
 *
 * Researchers publishing a malware corpus often put the actual files in a MEGA
 * folder and cite the link in their writeup. The link is then recorded here as a
 * mirror and never fetched, because nothing in the toolchain speaks MEGA: rclone's
 * backend wants an account, and the public-folder API is not plain HTTP GET. So the
 * bytes sit one hop away from a record that reads "unavailable".
 *
 * This speaks enough of that API to walk a folder and pull files out of it. Nothing
 * is executed; files are written to disk and measured, which is the only thing this
 * corpus ever does with them.
 *
 * The scheme, briefly, because it is not obvious from the wire format: the fragment
 * of the share URL is the folder key. Every node carries an "k" of the form
 * "<handle>:<base64>", whose value decrypts under the folder key with AES-ECB. A
 * folder node's key is 16 bytes as-is; a file node's is 32 bytes that fold in half
 * by XOR to give the 16-byte content key, with the discarded half holding the CTR
 * nonce and the MAC. Attributes decrypt under that key with AES-CBC and a zero IV
 * and arrive as "MEGA" followed by JSON. File contents decrypt with AES-CTR.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const API = "https://g.api.mega.co.nz/cs";

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/fetch-mega-folder.js --url URL [options]\n\n` +
    `  --url URL        Public folder link, https://mega.nz/folder/<id>#<key>\n` +
    `  --out DIR        Download files into this directory (default: list only)\n` +
    `  --match REGEX    Only download files whose path matches\n` +
    `  --max-mb N       Skip files larger than this (default: 2048)\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = { maxMB: 2048 };
  for (let i = 2; i < argv.length; i += 1) {
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) usage(1);
      i += 1;
      return next;
    };
    const arg = argv[i];
    if (arg === "--url") options.url = value();
    else if (arg === "--out") options.out = path.resolve(value());
    else if (arg === "--match") options.match = new RegExp(value(), "i");
    else if (arg === "--max-mb") options.maxMB = Number(value());
    else if (arg === "--help") usage(0);
    else usage(1);
  }
  if (!options.url) usage(1);
  return options;
}

const b64 = s => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") +
  "=".repeat((4 - (s.length % 4)) % 4), "base64");

function ecbDecrypt(key, data) {
  const d = crypto.createDecipheriv("aes-128-ecb", key, null);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(data), d.final()]);
}

// A file key is 32 bytes: the first half XOR the second gives the content key,
// and the half that is discarded carries the CTR nonce and the meta-MAC.
function unpackFileKey(k32) {
  const key = Buffer.alloc(16);
  for (let i = 0; i < 16; i += 1) key[i] = k32[i] ^ k32[i + 16];
  return { key, nonce: k32.subarray(16, 24) };
}

function decryptAttributes(key, attr) {
  if (!attr || attr.length % 16 !== 0) return null;
  const d = crypto.createDecipheriv("aes-128-cbc", key, Buffer.alloc(16));
  d.setAutoPadding(false);
  const out = Buffer.concat([d.update(attr), d.final()]).toString("utf8").replace(/\0+$/, "");
  if (!out.startsWith("MEGA")) return null;
  try {
    return JSON.parse(out.slice(4));
  } catch (_) {
    return null;
  }
}

let seq = Math.floor(Math.random() * 1e9);
async function api(folderId, payload) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    seq += 1;
    const r = await fetch(`${API}?id=${seq}&n=${folderId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify([payload]),
    });
    const body = await r.json();
    // MEGA answers a bare negative number for transient errors such as -3 (again).
    if (typeof body === "number" || (Array.isArray(body) && typeof body[0] === "number" && body[0] < 0)) {
      await new Promise(s => setTimeout(s, 2000 * (attempt + 1)));
      continue;
    }
    return Array.isArray(body) ? body[0] : body;
  }
  throw new Error("MEGA API kept returning a transient error");
}

async function main() {
  const options = parseArgs(process.argv);
  const m = options.url.match(/folder\/([^#]+)#([^/?]+)/);
  if (!m) throw new Error("not a public folder link: expected https://mega.nz/folder/<id>#<key>");
  const [, folderId, keyText] = m;
  const folderKey = b64(keyText).subarray(0, 16);

  const listing = await api(folderId, { a: "f", c: 1, r: 1, ca: 1 });
  const nodes = new Map();
  for (const n of listing.f || []) {
    // A node's "k" carries one "<handle>:<key>" pair per share it is reachable
    // through, joined by "/". Only the pair belonging to this share decrypts under
    // the folder key, and the cheapest way to find it is to try each and keep the
    // one whose attributes come back with the MEGA marker.
    const isFile = n.t === 0;
    let key = null; let nonce = null; let attrs = null;
    for (const pair of String(n.k || "").split("/")) {
      const raw = pair.split(":")[1];
      if (!raw) continue;
      const encoded = b64(raw);
      if (encoded.length % 16 !== 0) continue;
      let decoded;
      try {
        decoded = ecbDecrypt(folderKey, encoded);
      } catch (_) {
        continue;
      }
      const candidate = isFile ? unpackFileKey(decoded) : { key: decoded.subarray(0, 16), nonce: null };
      let got = null;
      try {
        got = decryptAttributes(candidate.key, b64(n.a));
      } catch (_) {
        continue;
      }
      if (got && got.n) { key = candidate.key; nonce = candidate.nonce; attrs = got; break; }
    }
    if (!key) { nodes.set(n.h, { handle: n.h, parent: n.p, isFile, size: n.s, key: null, nonce: null, name: `<undecodable:${n.h}>` }); continue; }
    nodes.set(n.h, { handle: n.h, parent: n.p, isFile, size: n.s, key, nonce, name: attrs.n });
  }
  const fullPath = node => {
    const parts = [];
    let cur = node;
    while (cur) { parts.unshift(cur.name); cur = nodes.get(cur.parent); }
    return parts.join("/");
  };

  const files = [...nodes.values()].filter(n => n.isFile).sort((a, b) => fullPath(a).localeCompare(fullPath(b)));
  process.stdout.write(`${files.length} files in ${folderId}\n`);
  for (const f of files) process.stdout.write(`  ${String(f.size).padStart(12)}  ${fullPath(f)}\n`);
  if (!options.out) return;

  fs.mkdirSync(options.out, { recursive: true });
  for (const f of files) {
    const rel = fullPath(f);
    if (options.match && !options.match.test(rel)) continue;
    if (f.size > options.maxMB * 1024 * 1024) {
      process.stdout.write(`  SKIP (${f.size} bytes over limit) ${rel}\n`);
      continue;
    }
    const link = await api(folderId, { a: "g", g: 1, n: f.handle });
    if (!link || !link.g) { process.stdout.write(`  FAIL no link for ${rel}\n`); continue; }
    // MEGA hands out plain-http storage nodes that Node's fetch intermittently
    // refuses with a bare "fetch failed". curl has no trouble with them, so it is
    // the fallback rather than a lost file.
    let cipher;
    try {
      const resp = await fetch(link.g);
      if (!resp.ok) throw new Error(`status ${resp.status}`);
      cipher = Buffer.from(await resp.arrayBuffer());
    } catch (_) {
      const tmp = path.join(options.out, `.download-${f.handle}`);
      execFileSync("curl", ["-s", "--max-time", "1800", "-o", tmp, link.g], { stdio: "ignore" });
      cipher = fs.readFileSync(tmp);
      fs.unlinkSync(tmp);
    }
    const counter = Buffer.concat([f.nonce, Buffer.alloc(8)]);
    const d = crypto.createDecipheriv("aes-128-ctr", f.key, counter);
    const plain = Buffer.concat([d.update(cipher), d.final()]);
    const dest = path.join(options.out, rel.replace(/[^\w./-]/g, "_"));
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, plain);
    const sha = crypto.createHash("sha256").update(plain).digest("hex");
    process.stdout.write(`  ${sha}  ${plain.length}  ${rel}\n`);
  }
}

main().catch(e => { process.stderr.write(`${e.message}\n`); process.exit(1); });
