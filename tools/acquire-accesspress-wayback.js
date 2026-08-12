#!/usr/bin/env node

/*
 * Acquire compromised AccessPress plugin ZIPs captured from the vendor site.
 *
 * The capture inventory is the result of a CDX prefix query over the compromise
 * window. Archives are listed and individual PHP files are read with unzip; no
 * archive member is extracted, imported, or executed.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..");
const ATTACK_DIR = path.join(ROOT, "oss", "attacks", "accesspress");
const SAMPLE_ROOT = path.join(ATTACK_DIR, "samples");
const META_FILE = path.join(ATTACK_DIR, "meta.yaml");
const MANIFEST_FILE = path.join(SAMPLE_ROOT, "manifest.yaml");
const REPORT_FILE = path.join(ATTACK_DIR, "vendor-wayback.yaml");
const DEFAULT_FORAGER = "/private/tmp/forager-purl";
const ORIGINAL_PREFIX = "https://accesspressthemes.com/plugin-repo/plugins/";
const CDX_QUERY = "https://web.archive.org/cdx/search/cdx?url=accesspressthemes.com%2Fplugin-repo%2Fplugins%2F*&from=20210901&to=20211015&output=json&fl=timestamp%2Coriginal%2Cstatuscode%2Cmimetype%2Cdigest%2Clength&filter=statuscode%3A200&filter=mimetype%3Aapplication%2Fzip&collapse=urlkey";

// timestamp, plugin slug, CDX digest, CDX response length
const CAPTURES = [
  ["20211011003032", "accesspress-custom-css", "FYUTZZUHPKWIECDHWVUNWPE7AAHLTUJD", 205900],
  ["20211012164345", "accesspress-custom-post-type", "BRNIBBJM7XC7R4FEFA4X65EK25GXGNSR", 589837],
  ["20211011233231", "accesspress-facebook-auto-post", "7SWF7SWADNZYUPQJCUCH7X3UVXNNY6SN", 1033870],
  ["20211010195228", "accesspress-pinterest", "7IGXI77DZ4Z3BE3W4RRZGM4DMUO77JH4", 1226815],
  ["20211010225552", "accesspress-social-icons", "S6NQBZWFDB3IDTOCULLVH5S3SNRLFLOP", 1923221],
  ["20211011003034", "accesspress-social-login-lite", "IJL3OEO5HLMCVM6JUPCALSZBOTADYGUV", 2005855],
  ["20211013083117", "accesspress-social-share", "WXNZLKBLIAYD4LF3O3Y3PXVRE6WLVXFQ", 2725214],
  ["20211013083119", "accesspress-twitter-feed", "5SYWIVQ2FKIMR2E5YNOHHRAMBOHCGBRB", 726363],
  ["20211010223932", "ap-pricing-tables-lite", "L2XO3E2EFRR7QWNWV3VGF7XB6QYH2WI7", 1251480],
  ["20211014085018", "easy-side-tab-cta", "LNEJK4JNBRQPDJI34TL5T3KL3MHJ3NH4", 981521],
  ["20211011184018", "everest-coming-soon-lite", "MTULZMRHOEGJMGM3QTC23BVRHDAR5YA6", 5675241],
  ["20211012174356", "everest-faq-manager-lite", "YIWRCM7H2G5O7SN67HWVA4XOR3BNJTKW", 1204509],
  ["20211014085017", "everest-google-places-reviews-lite", "MTDIGQW6ZJVVFN5SSDFZTJNVEMSLZUGF", 1029369],
  ["20211014090525", "everest-review-lite", "AER4VRF52SPKLVQKN3NSIPAFO4AI52VW", 1470856],
  ["20211013231842", "everest-tab-lite", "D2EG2YTCMROX6VV5ZL2NLVE6BPZBUQCF", 1588883],
  ["20211013083120", "everest-timeline-lite", "VL67MTHS54H4BTOPBK3INBE7FCIAS5FT", 1120663],
  ["20211011113822", "smart-logo-showcase-lite", "EURS57DHRBGX7VHKKWIO245F6I56ST7X", 1284313],
  ["20211013233346", "smart-scroll-posts", "7ILI2U3CVXZ7XUTCLA6D3LRDYKNUYYEP", 665760],
  ["20211014090523", "smart-scroll-to-top-lite", "HXSNUKNW7SETWDX7VOPATSI6YESDLFYR", 6128145],
  ["20211011184016", "total-team-lite", "4ELCANHD7OXYTLRXBOCVK3UJGN3WXXNV", 2073783],
  ["20211011003021", "ultimate-author-box-lite", "5OR72WPE3U5WIJ2SICAVCPP5QAY4JZMA", 1264627],
  ["20211011034408", "woo-badge-designer-lite", "AMDN7QD4FWPUPGVFWMAVMZ2X2SIB4VBD", 2369647],
  ["20211012171350", "wp-blog-manager-lite", "OLAMABXF5BVHGPAFSBUFE353FQ752SBM", 1387890],
  ["20211010223944", "wp-comment-designer-lite", "YJRYHIAK7HCZELHMRUGGK7GQQKFXAX24", 1513946],
  ["20211014090527", "wp-cookie-user-info", "C5VRU3FSXTXJG7QYPWZZNWK4OTOYQWLH", 2460805],
  ["20211011233228", "wp-popup-banners", "ZMJNDK6ZZ56CSG64CYRYTFS5RUKBU674", 772562],
  ["20211014090521", "wp-product-gallery-lite", "OVZTO43TSZPKWMUUHHR2J23ZYM6XWQJT", 1402834],
].map(([timestamp, slug, cdxDigest, cdxLength]) => ({ timestamp, slug, cdxDigest, cdxLength }));

function parseArgs(argv) {
  const options = { fetch: false, concurrency: 3, forager: DEFAULT_FORAGER, only: new Set() };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      if (++i >= argv.length) throw new Error(`missing value for ${arg}`);
      return argv[i];
    };
    if (arg === "--fetch") options.fetch = true;
    else if (arg === "--concurrency") options.concurrency = Number.parseInt(value(), 10);
    else if (arg === "--forager") options.forager = path.resolve(value());
    else if (arg === "--only") options.only = new Set(value().split(",").map(x => x.trim()).filter(Boolean));
    else if (arg === "--help" || arg === "-h") {
      process.stdout.write("Usage: node tools/acquire-accesspress-wayback.js [--fetch] [--concurrency N] [--forager PATH] [--only slug,...]\n");
      process.exit(0);
    } else throw new Error(`unknown argument: ${arg}`);
  }
  if (!Number.isInteger(options.concurrency) || options.concurrency < 1 || options.concurrency > 8) {
    throw new Error("--concurrency must be between 1 and 8");
  }
  return options;
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function replayURL(capture) {
  return `https://web.archive.org/web/${capture.timestamp}id_/${ORIGINAL_PREFIX}${capture.slug}.zip`;
}

function originalURL(capture) {
  return `${ORIGINAL_PREFIX}${capture.slug}.zip`;
}

function listArchive(file) {
  return execFileSync("unzip", ["-Z1", file], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 })
    .split(/\r?\n/).filter(Boolean);
}

function readMember(file, member) {
  return execFileSync("unzip", ["-p", file, member], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
}

function inspectArchive(file) {
  const members = listArchive(file);
  const dropper = members.find(x => /(^|\/)inital\.php$/i.test(x));
  if (!dropper) throw new Error("archive does not contain inital.php");

  const php = members.filter(x => /\.php$/i.test(x));
  const shallow = php.sort((a, b) => a.split("/").length - b.split("/").length).slice(0, 48);
  const texts = new Map();
  for (const member of [dropper, ...shallow]) {
    if (!texts.has(member)) texts.set(member, readMember(file, member));
  }
  const joined = [...texts.values()].join("\n");
  const indicators = ["wp-theme-connect.com", "wp_is_mobile_fix"].filter(x => joined.includes(x));
  if (!indicators.length) throw new Error("inital.php found, but no AccessPress backdoor indicator was found");

  let version = "";
  for (const text of texts.values()) {
    const match = text.match(/^\s*(?:\/\*+|\*|\/\/|#)?\s*Version:\s*([^\r\n*]+)/im);
    if (match) {
      version = match[1].trim();
      break;
    }
  }
  return { members: members.length, dropper, indicators, version };
}

function runForager(binary, url, outputDir) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, ["fetch", "-o", outputDir, url], { stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", data => { output = `${output}${data}`.slice(-12000); });
    child.stderr.on("data", data => { output = `${output}${data}`.slice(-12000); });
    child.on("error", reject);
    child.on("close", code => code === 0 ? resolve(output) : reject(new Error(output.trim() || `forager exited ${code}`)));
  });
}

function expectedVersions() {
  const document = yaml.load(fs.readFileSync(META_FILE, "utf8"));
  const attack = Array.isArray(document) ? document[0] : document;
  return new Map((attack.artifacts || []).map(artifact => [String(artifact.id), (artifact.versions || []).map(String)]));
}

function incidentArtifacts() {
  const document = yaml.load(fs.readFileSync(META_FILE, "utf8"));
  const attack = Array.isArray(document) ? document[0] : document;
  return attack.artifacts || [];
}

function existingResult(capture) {
  const filename = `${capture.timestamp}-${capture.slug}.zip`;
  const file = path.join(SAMPLE_ROOT, capture.slug, "during", filename);
  if (!fs.existsSync(file)) return null;
  const inspected = inspectArchive(file);
  return {
    ...capture,
    status: "acquired",
    existing: true,
    filename,
    relativePath: path.relative(SAMPLE_ROOT, file),
    sha256: sha256(file),
    size: fs.statSync(file).size,
    ...inspected,
  };
}

async function acquire(capture, options) {
  const existing = existingResult(capture);
  if (existing) return existing;
  if (!options.fetch) return { ...capture, status: "not_acquired" };

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), `accesspress-${capture.slug}-`));
  try {
    await runForager(options.forager, replayURL(capture), temp);
    // Forager namespaces immutable replay downloads under wayback/ and uses
    // the capture timestamp in the filename so distinct captures cannot clash.
    const source = path.join(temp, "wayback", `${capture.timestamp}-${capture.slug}.zip`);
    const sourceSidecar = `${source}.forage.json`;
    if (!fs.existsSync(source) || !fs.existsSync(sourceSidecar)) {
      throw new Error("forager did not produce the expected archive and provenance sidecar");
    }
    const inspected = inspectArchive(source);
    const filename = `${capture.timestamp}-${capture.slug}.zip`;
    const destinationDir = path.join(SAMPLE_ROOT, capture.slug, "during");
    const destination = path.join(destinationDir, filename);
    fs.mkdirSync(destinationDir, { recursive: true });
    fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
    const sidecar = JSON.parse(fs.readFileSync(sourceSidecar, "utf8"));
    sidecar.artifact.filename = filename;
    sidecar.fetch.original_url ||= originalURL(capture);
    fs.writeFileSync(`${destination}.forage.json`, `${JSON.stringify(sidecar, null, 2)}\n`);
    return {
      ...capture,
      status: "acquired",
      existing: false,
      filename,
      relativePath: path.relative(SAMPLE_ROOT, destination),
      sha256: sha256(destination),
      size: fs.statSync(destination).size,
      ...inspected,
    };
  } catch (error) {
    return { ...capture, status: "failed", error: String(error.message || error).slice(-4000) };
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

async function mapConcurrent(items, concurrency, fn) {
  const results = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await fn(items[index]);
      const result = results[index];
      process.stderr.write(`${result.status}: ${result.slug}${result.version ? ` @ ${result.version}` : ""}\n`);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

function updateManifest(results, versions) {
  const manifest = yaml.load(fs.readFileSync(MANIFEST_FILE, "utf8")) || { schema_version: 1, samples: [] };
  manifest.samples ||= [];
  for (const result of results.filter(x => x.status === "acquired")) {
    const expected = versions.get(result.slug) || [];
    const version = result.version || (expected.length === 1 ? expected[0] : "");
    const entry = {
      artifact_id: result.slug,
      phase: "during",
      classification: "malicious",
      coordinate: version ? `pkg:wordpress/${result.slug}@${version}` : `pkg:wordpress/${result.slug}`,
      ...(version ? { version } : {}),
      filename: result.filename,
      path: result.relativePath,
      sha256: result.sha256,
      size: result.size,
      source: {
        url: replayURL(result),
        original_url: originalURL(result),
        retrieved_at: JSON.parse(fs.readFileSync(path.join(SAMPLE_ROOT, `${result.relativePath}.forage.json`), "utf8")).fetch.at,
        kind: "web_archive",
      },
      verification: {
        status: "probable_exact",
        basis: [
          "wayback_original_replay",
          `wayback_cdx_digest_${result.cdxDigest}`,
          "payload_file_inital.php",
          ...result.indicators.map(x => `payload_indicator_${x}`),
          "measured_sha256",
        ],
      },
      notes: [
        `The archived vendor ZIP contains ${result.dropper} and AccessPress backdoor indicators.`,
        ...(expected.length && version && !expected.includes(version)
          ? [`Observed plugin version ${version} differs from dataset version(s): ${expected.join(", ")}.`]
          : []),
      ],
    };
    const index = manifest.samples.findIndex(sample => sample.artifact_id === result.slug && sample.classification === "malicious");
    if (index === -1) manifest.samples.push(entry);
    else manifest.samples[index] = entry;
  }
  fs.writeFileSync(MANIFEST_FILE, yaml.dump(manifest, { noRefs: true, lineWidth: 100, sortKeys: false }));
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const versions = expectedVersions();
  const artifacts = incidentArtifacts();
  const selected = CAPTURES.filter(capture => !options.only.size || options.only.has(capture.slug));
  const results = await mapConcurrent(selected, options.concurrency, capture => acquire(capture, options));
  if (options.fetch) updateManifest(results, versions);

  const report = {
    schema_version: 1,
    incident_id: "accesspress-themes",
    scope: {
      compromise_window: { from: "2021-09-01", to: "2021-10-15" },
      source_prefix: `${ORIGINAL_PREFIX}*.zip`,
      cdx_query: CDX_QUERY,
      discovery_source: "https://blog.wpsec.com/accesspress-hack-underlines-the-importance-of-core-file-monitoring/",
    },
    interpretation: [
      "These are original-byte Wayback replays of ZIPs served by the compromised AccessPress vendor site.",
      "A capture is accepted only when it contains inital.php and at least one documented backdoor indicator.",
      "No theme ZIP captures were returned for the historically advertised /downloads/*.zip path in the compromise window.",
    ],
    captures: results.map(result => ({
      artifact_id: result.slug,
      timestamp: result.timestamp,
      original_url: originalURL(result),
      replay_url: replayURL(result),
      cdx_digest: result.cdxDigest,
      cdx_length: result.cdxLength,
      status: result.status,
      ...(result.sha256 ? { sha256: result.sha256, size: result.size } : {}),
      ...(result.version ? { observed_version: result.version } : {}),
      ...(result.dropper ? { dropper_path: result.dropper, indicators: result.indicators } : {}),
      ...(result.error ? { error: result.error } : {}),
    })),
    unresolved_vendor_artifacts: artifacts
      .filter(artifact => !CAPTURES.some(capture => capture.slug === String(artifact.id)))
      .map(artifact => ({
        artifact_id: String(artifact.id),
        kind: String(artifact.kind || "unknown"),
        affected_versions: (artifact.versions || []).map(String),
        status: "vendor_malicious_bytes_not_recovered",
        reason: artifact.kind === "theme"
          ? "No ZIP capture was returned for the historically advertised /downloads/*.zip theme path in the compromise window."
          : "No ZIP capture was returned by the plugin-repo/plugins/*.zip CDX query in the compromise window.",
      })),
  };
  fs.writeFileSync(REPORT_FILE, yaml.dump(report, { noRefs: true, lineWidth: 120, sortKeys: false }));

  const acquired = results.filter(x => x.status === "acquired").length;
  const failed = results.filter(x => x.status === "failed").length;
  process.stdout.write(`AccessPress Wayback: ${acquired}/${results.length} acquired, ${failed} failed; report ${path.relative(ROOT, REPORT_FILE)}\n`);
  if (failed) process.exitCode = 1;
}

main().catch(error => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
