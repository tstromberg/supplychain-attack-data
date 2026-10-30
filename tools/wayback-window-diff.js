#!/usr/bin/env node

/*
 * Find the tampered copy of a live URL among its Internet Archive captures.
 *
 * A CDN script, an updater endpoint, or any other mutable URL has no version to
 * ask for: the artifact is whatever the host returned at a moment in time. When
 * the incident window is known, the Archive often holds captures inside it, and
 * the tampered one can be identified without trusting any report — by comparing
 * every distinct capture in the window against captures from outside it.
 *
 * This tool only downloads and compares bytes. It never executes what it fetches.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const CDX = "http://web.archive.org/cdx/search/cdx";

function usage(exitCode = 0) {
  process.stderr.write(`Usage: node tools/wayback-window-diff.js --url URL --from YYYYMMDD --to YYYYMMDD [options]\n\n` +
    `  --url URL          Original URL as it was served (no web.archive.org prefix)\n` +
    `  --from YYYYMMDD    First day of the incident window\n` +
    `  --to YYYYMMDD      Last day of the incident window\n` +
    `  --before YYYYMMDD  Baseline day before the window (default: 30 days before --from)\n` +
    `  --after YYYYMMDD   Baseline day after the window (default: 30 days after --to)\n` +
    `  --out DIR          Keep every fetched capture here for inspection\n` +
    `  --limit N          Maximum distinct in-window captures to fetch (default: 40)\n` +
    `  --help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = { limit: 40 };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) usage(1);
      i += 1;
      return next;
    };
    if (arg === "--url") options.url = value();
    else if (arg === "--from") options.from = value();
    else if (arg === "--to") options.to = value();
    else if (arg === "--before") options.before = value();
    else if (arg === "--after") options.after = value();
    else if (arg === "--out") options.out = path.resolve(value());
    else if (arg === "--limit") options.limit = Number(value());
    else if (arg === "--help") usage(0);
    else usage(1);
  }
  if (!options.url || !options.from || !options.to) usage(1);
  return options;
}

function shiftDay(day, days) {
  const date = new Date(Date.UTC(Number(day.slice(0, 4)), Number(day.slice(4, 6)) - 1, Number(day.slice(6, 8))));
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10).replace(/-/g, "");
}

// CDX answers 503 under load and occasionally drops the connection. Retry a few
// times before giving up, because an empty answer here reads as "nothing archived"
// and that is the one wrong conclusion this tool must not reach.
async function cdx(url, from, to, extra = {}) {
  const query = new URLSearchParams({ url, output: "json", from, to, filter: "statuscode:200", ...extra });
  let lastError = null;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    if (attempt) await new Promise(resolve => setTimeout(resolve, 5000 * attempt));
    try {
      const response = await fetch(`${CDX}?${query}`);
      if (!response.ok) {
        lastError = new Error(`CDX ${response.status} for ${url}`);
        continue;
      }
      const text = await response.text();
      if (!text.trim()) return [];
      return JSON.parse(text).slice(1).map(row => ({ timestamp: row[1], digest: row[5], length: Number(row[6]) }));
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error(`CDX failed for ${url}`);
}

// id_ replays the original response, which for a compressed resource is the
// gzip container rather than the resource. fetch() decodes it, and the decode
// is recorded by the caller as a derivation step.
async function capture(url, timestamp) {
  // A replay can fail on its own (the Archive rate limits, and some captures
  // replay empty). One bad capture is not a reason to abandon the comparison.
  try {
    const response = await fetch(`https://web.archive.org/web/${timestamp}id_/${url}`);
    if (!response.ok) return null;
    const body = Buffer.from(await response.arrayBuffer());
    if (!body.length) return null;
    return { timestamp, body, sha256: crypto.createHash("sha256").update(body).digest("hex") };
  } catch (_) {
    return null;
  }
}

// Locate where the tampered copy stops matching the baseline. Trimming the common
// prefix and suffix brackets the change; on a minified file the bracket usually
// runs past the injection, because unrelated bytes later in the file also moved.
// The honest signal is the length delta, so report that first and the bracket as
// a place to start reading, not as the payload.
function changedRegion(baseline, candidate) {
  const a = baseline.toString("latin1");
  const b = candidate.toString("latin1");
  let head = 0;
  while (head < a.length && head < b.length && a[head] === b[head]) head += 1;
  let tail = 0;
  while (tail < a.length - head && tail < b.length - head &&
    a[a.length - 1 - tail] === b[b.length - 1 - tail]) tail += 1;
  return {
    offset: head,
    delta: b.length - a.length,
    region: b.slice(head, b.length - tail),
    baselineRegion: a.slice(head, a.length - tail),
  };
}

async function main() {
  const options = parseArgs(process.argv);
  const before = options.before || shiftDay(options.from, -30);
  const after = options.after || shiftDay(options.to, 30);
  if (options.out) fs.mkdirSync(options.out, { recursive: true });

  const baselines = [];
  for (const [label, day] of [["before", before], ["after", after]]) {
    // One unreachable baseline is a weaker comparison, not a failed run.
    let rows = [];
    try {
      rows = await cdx(options.url, day, day);
    } catch (error) {
      process.stdout.write(`baseline ${label} ${day}: ${error.message}\n`);
      continue;
    }
    if (!rows.length) {
      process.stdout.write(`baseline ${label} ${day}: no capture\n`);
      continue;
    }
    const got = await capture(options.url, rows[0].timestamp);
    if (!got) continue;
    baselines.push({ label, ...got });
    process.stdout.write(`baseline ${label} ${got.timestamp}  ${got.sha256}  ${got.body.length} bytes\n`);
  }
  if (!baselines.length) {
    process.stderr.write("No baseline capture outside the window; cannot tell tampered from normal.\n");
    process.exit(2);
  }
  if (baselines.length === 2 && baselines[0].sha256 === baselines[1].sha256) {
    process.stdout.write("baselines agree: the file did not otherwise change around the window\n");
  }

  const rows = await cdx(options.url, options.from, options.to, { collapse: "digest" });
  process.stdout.write(`\n${rows.length} distinct in-window captures\n`);
  const seen = new Map();
  for (const row of rows.slice(0, options.limit)) {
    const got = await capture(options.url, row.timestamp);
    if (!got) continue;
    if (seen.has(got.sha256)) continue;
    seen.set(got.sha256, got);
    const known = baselines.find(b => b.sha256 === got.sha256);
    if (options.out) fs.writeFileSync(path.join(options.out, `${got.timestamp}.body`), got.body);
    if (known) {
      process.stdout.write(`  ${got.timestamp}  matches ${known.label} baseline\n`);
      continue;
    }
    const diff = changedRegion(baselines[0].body, got.body);
    const sign = diff.delta >= 0 ? "+" : "";
    process.stdout.write(`  ${got.timestamp}  DIFFERS  ${got.sha256}  ${got.body.length} bytes ` +
      `(${sign}${diff.delta} vs baseline, changed from offset ${diff.offset})\n`);
    if (diff.region.length) {
      process.stdout.write(`      reads: ${JSON.stringify(diff.region.slice(0, 400))}\n`);
    }
  }
  process.stdout.write(`\n${seen.size} distinct bodies fetched\n`);
}

main().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
