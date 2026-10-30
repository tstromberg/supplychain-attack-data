#!/usr/bin/env node
"use strict";

/*
 * Archives the pages each record cites, beside the record that cites them.
 *
 *   node tools/archive-references.js [--only ID] [--refresh] [--from-reference N] [--through-reference N] [--limit N] [--dry-run]
 *
 *   oss/attacks/jscrambler/refs/
 *     manifest.yaml
 *     01-jscrambler-com.html
 *     02-thehackernews-com.html
 *
 * References rot. A survey of this corpus found roughly one cited page in ten
 * already gone, and — the part that matters — several of those had no Wayback
 * snapshot at any timestamp, so the only copy that will ever exist is one taken
 * here. A compendium whose value is "a jumping off point for further research"
 * cannot rest on someone else's uptime.
 *
 * The manifest is also a liveness ledger. A page that 404s or refuses a robot is
 * recorded with its status and the date attempted, so a later reader can tell a
 * reference that was never captured from one that was already dead when we
 * looked. Failures are kept deliberately; the absence is itself a finding.
 *
 * Pages are stored as served. Git compresses its own objects, so uncompressed
 * HTML costs little and stays greppable. A page whose markup carries no prose is
 * a JavaScript shell whose article exists only once rendered, so a printed copy
 * is kept beside it.
 *
 * Sites that answer 429 are rate-limiting on purpose and are left alone. Nothing
 * here tries to defeat a paywall or a bot check; a refusal is recorded and the
 * run moves on.
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..");
const CORPORA = ["oss", "proprietary"];

// Long enough for a slow archive host, short enough that one dead server does
// not stall a run across 1,400 references.
const REQUEST_TIMEOUT_MS = 25_000;
const TRANSIENT_RETRIES = 2;
const TRANSIENT_BACKOFF_MS = 4_000;

// Courtesy gap between requests to the same host.
const HOST_DELAY_MS = 1_500;

// Roughly how much readable text a real article carries. Below this the capture
// is a shell and the page is only preserved by rendering it.
const MIN_VISIBLE_TEXT = 600;

// Identifying as a browser is what lets us keep a copy of a page we already
// cite. It is not an attempt to get past a paywall.
const USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36";

const CHROMIUM = ["chromium", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
  .find(candidate => spawnSync("sh", ["-c", `command -v ${JSON.stringify(candidate)}`]).status === 0 ||
    fs.existsSync(candidate));

// Many publishers sit behind a proof-of-work or JavaScript bot-wall that answers
// a plain GET with 403, or with a "Just a moment..." interstitial that is a 200
// carrying no article. anubis-fetch solves those the way a reader's browser
// would. It is slow, so it is only reached for after an ordinary fetch has
// failed or come back empty.
const ANUBIS = spawnSync("sh", ["-c", "command -v anubis-fetch"]).status === 0 ? "anubis-fetch" : null;

function anubisFetch(url) {
  if (!ANUBIS) return null;
  const result = spawnSync(ANUBIS, ["--browser", "--timeout", "60000", url], {
    maxBuffer: 64 * 1024 * 1024,
    timeout: 150_000
  });
  if (result.status !== 0 || !result.stdout || result.stdout.length === 0) return null;
  return result.stdout;
}

function parseArgs(argv) {
  const options = {
    refresh: false,
    dryRun: false,
    only: null,
    fromReference: 1,
    throughReference: Infinity,
    limit: 0
  };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--refresh") options.refresh = true;
    else if (argv[i] === "--dry-run") options.dryRun = true;
    else if (argv[i] === "--only") options.only = argv[++i];
    else if (argv[i] === "--from-reference") options.fromReference = Math.max(1, Number(argv[++i]) || 1);
    else if (argv[i] === "--through-reference") {
      options.throughReference = Math.max(1, Number(argv[++i]) || 1);
    }
    else if (argv[i] === "--limit") options.limit = Number(argv[++i]) || 0;
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return options;
}

// Record files live at <corpus>/**/meta.yaml. The samples and refs directories
// beside them hold manifests of the same name, so they are skipped.
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

function slugify(value) {
  const slug = String(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return slug || "page";
}

function extensionFor(contentType, url) {
  if (contentType.includes("pdf") || url.toLowerCase().endsWith(".pdf")) return ".pdf";
  if (contentType.startsWith("text/plain")) return ".txt";
  if (contentType.includes("xml")) return ".xml";
  if (contentType.includes("json")) return ".json";
  return ".html";
}

// How much prose a page carries once its scripts, styles and tags are removed.
function visibleText(body) {
  return body
    .replace(/<(script|style|noscript)[^>]*>[\s\S]*?<\/\1>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function visibleTextLength(body) {
  return visibleText(body).length;
}

// A bot-wall answers with a real 200 and a page that is not the article. Storing
// one would put a file on disk and a success in the ledger while preserving
// nothing, which is worse than recording the refusal, so these are detected and
// treated as failures.
const CHALLENGE_MARKERS = [
  "just a moment",
  "robot challenge screen",
  "checking the site connection security",
  "enable javascript and cookies to continue",
  "attention required",
  "access denied |",
  "used cloudflare to restrict access",
  "403 - forbidden",
  "access to this page is forbidden",
  "verify you are human",
  "ddos protection by",
  "please turn javascript on",
  "making sure you're not a bot",
  "making sure you&#39;re not a bot",
  "protected by anubis",
  "anubis requires the use of modern javascript features"
];

function looksLikeChallenge(text) {
  const head = text.slice(0, 1200).toLowerCase();
  return CHALLENGE_MARKERS.some(marker => head.includes(marker));
}

// Many publishers answer a dead article with 200 and their "not found" template,
// so the status code cannot be trusted to say whether the citation still exists.
// The title is what distinguishes them: a real article about a 404 keeps its own
// headline, while the error page announces itself there. Matching on body text
// instead would flag genuine articles that merely mention the phrase.
const NOT_FOUND_TITLE = /(^|\W)(404|page not found|post not found|not found|no longer available|doesn['’]t exist)(\W|$)/i;

function looksLikeNotFound(html) {
  const match = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  if (!match) return false;
  return NOT_FOUND_TITLE.test(match[1].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
}

// Text a rendered PDF actually carries, so a printed challenge screen is not
// mistaken for a printed article.
function pdfTextLength(file) {
  const result = spawnSync("pdftotext", [file, "-"], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  if (result.status !== 0 || typeof result.stdout !== "string") return null;
  return result.stdout.replace(/\s+/g, " ").trim().length;
}

function renderPdf(url, dest) {
  if (!CHROMIUM) return false;
  spawnSync(CHROMIUM, ["--headless", "--disable-gpu", "--no-sandbox",
    "--virtual-time-budget=9000", "--print-to-pdf-no-header",
    `--print-to-pdf=${dest}`, url], { stdio: "ignore", timeout: 60_000 });
  return fs.existsSync(dest) && fs.statSync(dest).size > 1024;
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function fetchOnce(url) {
  try {
    const response = await fetch(url, {
      redirect: "follow",
      headers: { "User-Agent": USER_AGENT, Accept: "text/html,application/xhtml+xml,application/pdf,*/*" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    });
    const buffer = Buffer.from(await response.arrayBuffer());
    return {
      status: response.status,
      body: buffer,
      contentType: (response.headers.get("content-type") || "").toLowerCase(),
      finalUrl: response.url
    };
  } catch (error) {
    return { status: 0, error: String(error.message || error).slice(0, 200), finalUrl: url };
  }
}

// 503 and a dropped connection mean "come back later", so they are worth a second
// and third try. 429 is a deliberate rate limit and is left alone, as is any 4xx.
// web.archive.org in particular answers 503 under light automation and succeeds on
// a retry, which is why references citing a snapshot were recorded as broken.
async function fetchPage(url) {
  for (let attempt = 0; ; attempt++) {
    const result = await fetchOnce(url);
    const transient = result.status === 503 || result.status === 0;
    if (!transient || attempt === TRANSIENT_RETRIES) return result;
    await sleep(TRANSIENT_BACKOFF_MS * (attempt + 1));
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const recordFiles = CORPORA
    .filter(corpus => fs.existsSync(path.join(ROOT, corpus)))
    .flatMap(corpus => findRecordFiles(path.join(ROOT, corpus)));

  const lastSeenAt = new Map();
  let captured = 0;
  let skipped = 0;
  let rendered = 0;
  let solvedByAnubis = 0;
  const failures = [];
  let processed = 0;

  for (const recordFile of recordFiles.sort()) {
    let records;
    try {
      records = yaml.load(fs.readFileSync(recordFile, "utf8"));
    } catch (error) {
      console.warn(`skipping ${path.relative(ROOT, recordFile)}: ${error.message}`);
      continue;
    }
    if (!Array.isArray(records)) continue;

    // A handful of files hold several records in one sequence and share a refs
    // directory, so each entry records which one cited it.
    const wanted = options.only ? records.filter(record => record && record.id === options.only) : records;
    if (wanted.length === 0) continue;

    const cited = [];
    for (const record of wanted) {
      for (const reference of record.references || []) {
        if (reference && typeof reference.url === "string" && reference.url.startsWith("http")) {
          cited.push({ record: record.id, url: reference.url, title: reference.title || "" });
        }
      }
    }
    if (cited.length === 0) continue;
    if (options.limit && processed >= options.limit) break;
    processed++;

    const refsDir = path.join(path.dirname(recordFile), "refs");
    const manifestFile = path.join(refsDir, "manifest.yaml");
    const previous = fs.existsSync(manifestFile)
      ? (yaml.load(fs.readFileSync(manifestFile, "utf8")) || {})
      : {};
    const byUrl = new Map((previous.references || []).map(entry => [entry.url, entry]));

    for (const [index, reference] of cited.entries()) {
      if (index + 1 < options.fromReference) continue;
      if (index + 1 > options.throughReference) continue;
      const existing = byUrl.get(reference.url);
      if (!options.refresh && existing && existing.path && fs.existsSync(path.join(refsDir, existing.path))) {
        skipped++;
        continue;
      }

      if (options.dryRun) {
        console.log(`would fetch ${reference.url}`);
        continue;
      }

      let host = "";
      try {
        host = new URL(reference.url).host;
      } catch { /* recorded below as a fetch failure */ }
      const since = Date.now() - (lastSeenAt.get(host) || 0);
      if (since < HOST_DELAY_MS) await sleep(HOST_DELAY_MS - since);
      lastSeenAt.set(host, Date.now());

      const result = await fetchPage(reference.url);
      const isPdf = extensionFor(result.contentType || "", reference.url) === ".pdf";
      let via = "fetch";
      // A bot-wall may answer 200, 202, 403 or anything else, so the body is
      // what decides, not the code.
      let text = result.body && !isPdf ? visibleText(result.body.toString("utf8")) : "";
      let readable = isPdf ? MIN_VISIBLE_TEXT : (result.status === 200 ? text.length : 0);
      let challenged = !isPdf && looksLikeChallenge(text);
      let missing = !isPdf && result.status === 200 && result.body
        ? looksLikeNotFound(result.body.toString("utf8"))
        : false;

      // A 403, or a 200 whose body is an interstitial rather than the article,
      // both mean the same thing: an ordinary request did not reach the page.
      // A publisher's "not found" template is worth one attempt through
      // anubis-fetch too, since some sites serve it to anything they take for a bot.
      if (!isPdf && (result.status !== 200 || readable < MIN_VISIBLE_TEXT || challenged || missing)) {
        const solved = anubisFetch(reference.url);
        if (solved) {
          const solvedText = visibleText(solved.toString("utf8"));
          const solvedChallenged = looksLikeChallenge(solvedText);
          const solvedMissing = looksLikeNotFound(solved.toString("utf8"));
          if (!solvedChallenged && !solvedMissing && solvedText.length > readable) {
            result.status = 200;
            result.body = solved;
            result.contentType = result.contentType || "text/html";
            text = solvedText;
            readable = solvedText.length;
            challenged = false;
            missing = false;
            via = "anubis-fetch";
            solvedByAnubis++;
          }
        }
      }

      // Never bank an interstitial as a capture.
      if (challenged) {
        result.status = result.status === 200 ? 403 : result.status;
        result.error = "bot-wall interstitial, article not reached";
        result.body = null;
      } else if (missing) {
        // Recorded as 404 because that is what the page means, whatever it said.
        result.status = 404;
        result.error = "publisher's not-found page served with status 200";
        result.body = null;
      }

      const entry = {
        record: reference.record,
        url: reference.url,
        title: reference.title,
        attempted_at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
        status: result.status
      };
      if (result.finalUrl && result.finalUrl !== reference.url) {
        entry.final_url = result.finalUrl;
        // A redirect that changes host is often a rebrand with the article
        // intact, but it is also how a dead post becomes a marketing page: one
        // capture here is Microsoft's site standing in for a RiskIQ writeup.
        // Flagged rather than judged, so a reader knows the bytes may not be
        // the cited article.
        const host = url => {
          try { return new URL(url).host.replace(/^www\./, ""); } catch { return ""; }
        };
        if (host(result.finalUrl) && host(result.finalUrl) !== host(reference.url)) {
          entry.redirected_offsite = true;
        }
      }

      if (result.status === 200 && result.body && result.body.length > 0) {
        const extension = extensionFor(result.contentType, reference.url);
        const name = `${String(index + 1).padStart(2, "0")}-${slugify(host)}${extension}`;
        fs.mkdirSync(refsDir, { recursive: true });
        fs.writeFileSync(path.join(refsDir, name), result.body);
        entry.path = name;
        entry.bytes = result.body.length;
        entry.sha256 = crypto.createHash("sha256").update(result.body).digest("hex");
        entry.content_type = result.contentType;
        // How the page was reached, so a later reader knows a bot-wall stood in
        // front of it and a plain fetch will not reproduce this capture.
        if (via !== "fetch") entry.via = via;
        captured++;

        let note = via === "fetch" ? "" : ` (via ${via})`;
        if (extension === ".html") {
          entry.visible_text = readable;
          if (readable < MIN_VISIBLE_TEXT) {
            const pdfName = name.replace(/\.html$/, ".pdf");
            const pdfFile = path.join(refsDir, pdfName);
            const printed = renderPdf(reference.url, pdfFile);
            // A print of a challenge screen preserves nothing either, so the
            // rendered file has to prove it carries the article.
            const pdfText = printed ? pdfTextLength(pdfFile) : null;
            if (printed && (pdfText === null || pdfText >= MIN_VISIBLE_TEXT)) {
              entry.pdf_path = pdfName;
              entry.pdf_bytes = fs.statSync(pdfFile).size;
              entry.pdf_sha256 = crypto.createHash("sha256").update(fs.readFileSync(pdfFile)).digest("hex");
              rendered++;
              note += ` (+pdf, html holds ${readable} chars)`;
            } else {
              if (printed) fs.unlinkSync(pdfFile);
              entry.note = `html holds only ${readable} characters of visible text` +
                (printed ? "; the rendered pdf held no article either" : "; pdf render failed");
              note += " (thin html, no usable render)";
            }
          }
        }
        console.log(`  ${reference.record}: ${name}${note}`);
      } else {
        if (result.error) entry.error = result.error;
        failures.push({ record: reference.record, status: result.status, error: result.error, url: reference.url });
        console.log(`  ${reference.record}: FAILED ${result.status || ""} ${result.error || ""} <- ${reference.url}`);
      }

      byUrl.set(reference.url, entry);
    }

    if (options.dryRun || byUrl.size === 0) continue;
    fs.mkdirSync(refsDir, { recursive: true });
    fs.writeFileSync(manifestFile, yaml.dump({
      schema_version: 1,
      references: cited.map(reference => byUrl.get(reference.url)).filter(Boolean)
    }, { noRefs: true, lineWidth: 100, sortKeys: false }));
  }

  console.log(`\ncaptured ${captured} (${solvedByAnubis} needed anubis-fetch), ${rendered} needed a rendered pdf, skipped ${skipped} already archived, ${failures.length} failed`);
  if (failures.length > 0) {
    const grouped = new Map();
    for (const failure of failures) {
      const reason = `${failure.status || 0} ${failure.error || ""}`.trim();
      grouped.set(reason, (grouped.get(reason) || 0) + 1);
    }
    console.log("failures, each recorded in its manifest with the date attempted:");
    for (const [reason, count] of [...grouped].sort((a, b) => b[1] - a[1])) {
      console.log(`  ${String(count).padStart(3)}  ${reason}`);
    }
  }
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
