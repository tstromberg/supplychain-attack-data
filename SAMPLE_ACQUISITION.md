# Sample acquisition plan

## Goal

Preserve an attributable copy of every affected distribution artifact identified by
this dataset, together with the closest confirmed non-malicious state before the
incident and, when one exists, the first remediated state after it.

The unit of collection is an immutable file, not merely a version string. A package
coordinate can name several files (for example, a Python sdist and wheels), and a
mutable tag or download URL can name different files before, during, and after an
incident.

## Repository layout

Samples live beside their attack description:

```text
<attack>/
├── meta.yaml
└── samples/
    ├── manifest.yaml
    └── <artifact-id>/
        ├── before/
        ├── during/
        └── after/
```

The three states mean:

- `before`: the newest confirmed non-affected artifact state before the incident.
- `during`: an artifact distributed during the affected window. It may be directly
  malicious, a loader or carrier, or merely affected context; the manifest records
  the more precise classification.
- `after`: the first confirmed remediated artifact state, when useful and available.

There is one artifact directory per `artifacts[].id` in `meta.yaml`. Empty phase
directories are not committed. A repeated baseline used by several affected versions
is stored once and related to all of them in the manifest.

Existing `artifacts/clean` and `artifacts/compromised` evidence remains valid. It can
be migrated after the convention has been exercised; acquisition must not discard or
silently replace it.

## Manifest

`samples/manifest.yaml` is maintained data, not a generated download log. Each entry
describes one immutable file:

```yaml
schema_version: 1
samples:
- artifact_id: example
  phase: during
  classification: malicious
  coordinate: pkg:npm/example@1.2.3
  version: 1.2.3
  filename: example-1.2.3.tgz
  path: example/during/example-1.2.3.tgz
  sha256: 0123456789abcdef...
  size: 12345
  source:
    url: https://registry.example/example-1.2.3.tgz
    retrieved_at: 2026-08-08T00:00:00Z
    kind: distribution
  verification:
    status: exact
    basis:
    - registry_sha512
  relates_to:
  - phase: before
    version: 1.2.2
  notes: []
```

Required fields are `artifact_id`, `phase`, `classification`, `filename`, `path`,
`sha256`, `size`, `source`, and `verification`. Use a Package URL in `coordinate`
when the ecosystem has one. Preserve the upstream filename unless it is unsafe or
ambiguous; if renamed, record the original filename in `notes`.

Every acquired file also carries a `<filename>.forage.json` sidecar. The sidecar is
capture-time evidence and must move with the file. It records the measured digest and
size, requested package identity, successful byte URL, retrieval time, collector, and
any registry or threat-feed record available to Forager. A sidecar returned by Hopper
is preserved verbatim after its artifact digest is checked; it is never replaced by a
new local record. The manifest adds incident-level interpretation, source-chain facts,
and unresolved discrepancies that do not belong in the immutable capture record.

Allowed classifications are:

- `malicious`: the file contains malicious code or a malicious payload.
- `carrier`: the file intentionally causes a malicious dependency or payload to be
  retrieved or executed.
- `affected`: the file belongs to the incident but direct malicious behavior in that
  exact file has not been established.
- `baseline_candidate`: preceding state selected by chronology but not yet confirmed
  clean.
- `clean`: preceding state confirmed non-malicious for this incident.
- `remediated`: state released after the incident to remove or block the compromise.

Unresolved records carry a status. `unavailable` means every configured source was
asked and none had the file. `timed_out` means the attempt was killed before any
source answered, which is not evidence about the artifact. A `timed_out` target is
re-queued by the next run without `--retry`; an `unavailable` one is not.

Verification statuses are:

- `exact`: bytes are bound to an authoritative digest or immutable source revision
  and have a measured SHA-256.
- `probable_exact`: original-looking distribution bytes without a contemporary
  authoritative digest.
- `tree_equivalent`: the historical source tree was recovered but original packaging
  bytes were not.
- `payload_only`: only an embedded payload or affected subset was recovered.
- `disputed`: available sources disagree.
- `unverified`: acquired but not sufficiently corroborated.

## Partial reconstruction inputs

When the original malicious distribution cannot be recovered, preserve any authentic
modified file, source diff, decoded payload, or injected hunk that can support a later
reconstruction. Store it in the artifact's `during` directory and classify the file by
what it contains; use `verification.status: payload_only` so it is never mistaken for
the original archive.

Preserve the source document or page from which the partial artifact was obtained.
The partial artifact's sidecar must identify that source file and digest and describe
every derivation step, such as extracting a diff block, decoding HTML entities,
normalizing line endings, or removing mailing-list quote prefixes. Do not invent
surrounding source context to make a fragment apply cleanly. A source capture and its
derived reconstruction input are separate corpus objects when both are useful.

## Complete tree reconstructions

A synthetic archive may be added only when retained evidence accounts for every file
in the affected distribution. A common valid case is an exact clean predecessor plus
one or more exact changed files, provided that a retained file manifest binds every
reused and replaced member to its size and content hash. A diff is sufficient only
when applying it produces the exact retained hash; a plausible patch without that
independent check is not sufficient. If even one member remains unknown, keep the
inputs as `payload_only` and do not create a synthetic complete archive.

Make the distinction visible without opening metadata: reconstructed archives must
include `RECONSTRUCTED` in the filename. Record them as `source.kind:
reconstructed_distribution` and `verification.status: tree_equivalent` when the
original archive ordering, headers, compression bytes, or authoritative whole-file
digest are unknown.

There is one exception: if the complete synthetic archive matches an authoritative
digest for the original distribution, it is byte-for-byte identical rather than
merely tree-equivalent. In that case preserve the upstream filename, use
`verification.status: exact`, and record both the authoritative digest source and the
measured match. Matching every member hash does not by itself satisfy this exception;
the digest must cover the archive as a whole.

The sample manifest must include a `source.reconstruction` record containing:

- the base artifact's path, version, digest, and member count;
- the retained complete-manifest URL, retrieval time, digest, hash algorithm, and
  expected member count;
- every added, replaced, or derived path, including its source and exact digest;
- the number of unchanged members reused from the base and how their hashes were
  checked; and
- the archive-format normalization used to make the synthetic file reproducible.

The adjacent `.forage.json` sidecar must repeat the reconstruction chain and state
that its own digest identifies the synthetic container rather than the removed
upstream archive. Verification must compare the reconstructed tree member-for-member
against the retained manifest, including paths, sizes, and content hashes.

## Discrepancy correction policy

Sample research is also an evidence review of the incident record. If a download,
hash, publication date, revision, URL, affected-version range, or distribution-side
claim conflicts with `meta.yaml` or a cited report, update the incident data rather
than leaving the contradiction only in a scratch note. Edit the source incident
`meta.yaml` and its references, then update the sample manifest's provenance or
`unresolved` record to explain what changed and why. Do not edit generated `_site`
HTML as the primary correction.

Use the least-destructive correction that makes the record accurate:

1. Preserve the original claim in a dated note when it is historically relevant,
   but label it disputed or unverified instead of presenting it as fact.
2. Correct artifact IDs, versions, revisions, hashes, dates, and locations when a
   primary source or measured bytes establish the replacement value.
3. If a purported sample is actually an article, landing page, clean comparator, or
   the wrong release, remove it from `samples`, retain useful context separately,
   and record the reason under `unresolved`.
4. If the correction changes the affected release set or incident scope, update the
   incident narrative and references together with the artifact list.
5. Re-run the relevant inventory and `make samples-verify`; include the resulting
   coverage change in the acquisition report or handoff note.

This rule applies to both OSS and proprietary incidents. A successful fetch does not
override stronger incident evidence, and an unavailable fetch does not justify
inventing a version, revision, or malicious/clean classification.

## Selecting the before state

Do not subtract version numbers or assume SemVer ordering. For each affected version:

1. Order releases by authoritative publication time.
2. Partition affected releases into contiguous incident windows.
3. Select the newest confirmed non-affected state before the first affected state in
   that window.
4. Relate every affected file in the window to that baseline. Content-addressed
   storage naturally deduplicates repeated files.
5. For a rewritten tag, mutable URL, or rolling update channel, select the prior state
   of the same coordinate or URL when it can be recovered.
6. Do not use `fixed_versions` as a substitute. They describe later remediation.
7. Keep an unresolved work item rather than inventing a baseline.

A chronological predecessor enters Hopper as `sighted` or `unknown` until its clean
status is verified. It must not be promoted automatically to `good` merely because it
predates the reported compromise.

## Acquisition order

For each target, search in this order:

1. Dataset SHA-256 in Hopper.
2. Exact Package URL and version in Hopper.
3. Official registry or vendor distribution endpoint.
4. Historical registry metadata, VCS objects, release assets, and update manifests.
5. Software Heritage, the Internet Archive, and other institutional archives.
6. Hash-indexed research exchanges, subject to their access and redistribution terms.
7. Incident researchers, registry response teams, vendors, and private collections.

Forager automates the hash-indexed portion of this sequence. With `--hash`, it
tries the optional local Hopper first, then MalwareBazaar, Triage, and Malshare using
locally configured API credentials. A PURL or URL supplied with the hash is attempted
before the hash services. Provider credentials are never written to the artifact
sidecar; successful provider metadata and the exact byte endpoint are.

`--hash` accepts MD5, SHA-1, and SHA-256, and both acquisition tools submit every
digest an artifact record publishes. This matters for older incidents, which were
frequently reported with an MD5 alone; MalwareBazaar indexes all three. Older Forager
builds spell the flag `--sha256` and reject `--hash` by printing usage and exiting
non-zero, which is indistinguishable from a miss. The tools therefore ask the binary
in hand which spelling it takes rather than assuming one.

Save the authoritative registry record or other provenance document even when its
artifact has been removed. Source trees reconstructed from version control are useful,
but must be marked `tree_equivalent` rather than represented as original distribution
bytes.

## Ecosystem lanes

- npm: use the packument publication times and each version's `dist.tarball`,
  `dist.shasum`, and `dist.integrity`. Preserve the tarball without running npm.
- PyPI: enumerate every sdist and wheel for the selected releases and verify the index
  SHA-256 for each file.
- WordPress: recover the exact SVN revision associated with the compromised and prior
  tag. A regenerated ZIP is not necessarily byte-identical to the historical download.
- Packagist/Composer: bind every version to the historical Git commit behind the tag.
  Rewritten tags require both pre-attack and attack-time objects; current tag archives
  alone are insufficient. Packagist's `p2` metadata gives each version a `dist.reference`
  commit SHA, so it states which object a fetch would actually return today. Composer
  dist URLs are `api.github.com` zipballs, and GitHub allows 60 unauthenticated API
  requests per hour. Export `GITHUB_TOKEN` for any lane larger than a few versions;
  Forager sends it only to `api.github.com` and never writes it to a sidecar.

  Do not assume a tag-rewrite incident is uniformly recoverable or uniformly restored.
  Decide per version, from the commit date and the payload, not from the incident.
- OCI: resolve tags to manifest digests and preserve the index, per-platform manifests,
  configuration, and layers.
- Installers, firmware, extensions, and update channels: prefer a published digest;
  otherwise corroborate the file through independent sources and preserve signing
  metadata where possible.

## Safety and storage

- Download bytes only. Do not install packages, execute installers, run lifecycle
  scripts, or build recovered source.
- Hash before parsing. Inspect archives with file-count, recursion-depth, output-size,
  and path-traversal limits.
- Keep samples content-addressed in Hopper when ingested; the repository layout is the
  human-facing incident view.
- Do not commit credentials, access tokens, or access-controlled download URLs. A
  Hopper endpoint may appear in a capture sidecar when it is the actual byte source;
  never include Hopper credentials or database connection strings.
- Record licensing, access, and redistribution restrictions for proprietary artifacts.
- Samples larger than 75 MB are stored xz-compressed. Both acquisition tools compress
  on capture, so the rule needs no separate step.

## Storage form

A sample's identity is the artifact's own bytes. `sha256` and `size` in the manifest
always describe the artifact, because that is what reported hashes, provenance
sidecars, and incident records are stated in. How the repository stores those bytes is
a separate fact, recorded in `storage`:

```yaml
  filename: JAVS.Viewer8.Setup_8.3.7.250-1.exe
  path: justice-av-solutions-javs-viewer/during/JAVS.Viewer8.Setup_8.3.7.250-1.exe.xz
  sha256: fe408e2df48237b11cb724fa51b6d5e9c74c8f5d5b2955c22962095c7ed70b2c
  size: 107965976
  storage:
    format: xz
    sha256: d0225464fad12c0de6d481d07a617ecb119f7c126821198d8a7dc63d67233271
    size: 107021848
```

`path` names the file on disk, `storage` describes the container, and `filename` and
`sha256` keep naming the artifact. The provenance sidecar keeps the artifact's own name
(`<artifact>.forage.json`), not the container's, because it describes the artifact.
`make samples-verify` checks the container's digest directly and the artifact's digest
by streaming the decompressed bytes, so a compressed sample is verified as strictly as
a plain one.

Anything above 75 MB is compressed; both acquisition tools do it at capture time.
An `.xz` file is only a container when the manifest says so — `xzutils` samples are
genuinely `.tar.xz` distributions and carry no `storage` block.

Compression does not rescue every file. Installers are usually compressed already and
barely shrink: three samples remain above GitHub's 100 MiB hard limit even as `.xz`
(JAVS Viewer at 107 MB and both Checkmarx artifacts at 114 MB and 117 MB). GitHub
refuses a push containing a blob that large, so those bytes cannot live in the
repository at all.

Such a sample is marked `storage.committed: false` and excluded by a `.gitignore`
written beside it, explaining the gap where someone will find it. Everything except the
bytes stays in git: the manifest entry with the artifact's digest and size, and the
provenance sidecar. The sample remains fully described and can be re-acquired or
restored from another store.

`make samples-verify` treats an absent uncommitted sample as the recorded state rather
than a fault, so a fresh clone passes, and reports the count separately:

```text
OK: 1243 samples in 260 manifests; hashes, sizes, paths, and provenance sidecars
verified; 3 too large for git and excluded from the repository
```

When the bytes are present locally they are verified in full, so excluding a sample
never weakens the check for whoever holds it. Both acquisition tools apply this
automatically: anything still over 100 MiB after compression is marked and ignored on
capture.

## Work phases

1. Generate a complete target inventory from every `meta.yaml`, including unexpanded
   ranges and artifacts without a precise version.
2. Reconcile known hashes and exact package coordinates against Hopper.
3. Acquire live npm and PyPI files and their before/after states.
4. Reconstruct WordPress SVN and Packagist/Git tag histories.
5. Acquire GitHub releases, OCI images, extensions, and other ecosystem artifacts.
6. Research proprietary, unversioned, and removed long-tail samples by hash and URL.
7. Publish a coverage report counting exact, reconstructed, partial, disputed, and
   unavailable targets separately.

## Repeatable OSS workflow

`tools/acquire-oss-samples.js` implements the npm/PyPI and reported-hash lanes. It
merges records into each incident's `samples/manifest.yaml`; it does not replace
hand-curated fields. The default command is inventory-only and refreshes
`OSS_SAMPLE_COVERAGE.yaml`:

```sh
node tools/acquire-oss-samples.js --no-before
```

High-yield live releases and their chronological predecessors can be populated with:

```sh
node tools/acquire-oss-samples.js --fetch --no-before --live-only \
  --hopper http://10.9.8.5:8081
node tools/acquire-oss-samples.js --fetch --before-only --live-only \
  --hopper http://10.9.8.5:8081
```

Reported hashes are a separate evidence lane because a metadata record can contain
several versions and several hashes without defining a mapping between them:

```sh
node tools/acquire-oss-samples.js --fetch --hash-only \
  --hopper http://10.9.8.5:8081
```

For removed packages, omit `--live-only` and use `--limit`, `--concurrency`, and
`--timeout` to run bounded archive batches. npm recovery then follows Forager's
registry/mirror, Wayback, jsDelivr, unpkg, socket.dev, and Software Heritage fallback
chain. Wayback original-byte replay is recorded as `probable_exact` unless a reported
digest confirms it; CDN, socket.dev, and Software Heritage reconstructions are
`tree_equivalent`.

The socket.dev lane recovers npm releases that were unpublished, and it is often the
only surviving source for a removed malicious version. It serves a package one file at
a time under a fifteen-second client-side rate limit, and Forager re-packs those files
into a tarball, so the result is a reconstruction and never the published archive
bytes. Wall-clock cost is roughly fifteen seconds per file in the package: five
minutes for a small package, well over an hour for a large one. Budget the timeout
accordingly. A ten-second timeout once recorded 633 recoverable npm and PyPI releases
as `unavailable`; those records have since been corrected to `timed_out`.

### Per-domain pacing

Forager paces requests per domain, but the schedule lives in the process. One Forager
process per target restarts it every time, so a long queue sends an unpaced first
request per target, and every extra concurrent process multiplies the rate against the
same host. `acquire-oss-samples.js` therefore passes many PURLs to a single process
with `--batch`, and defaults `--concurrency` to 1. Raising concurrency multiplies the
per-domain rate by that factor; it is not free parallelism.

Downloaded bytes are matched back to their target through the capture sidecar's
`package.purl`, not by filename, so a batch can be mapped without guessing. A target
the batch did not produce is recorded unresolved with the Forager log line naming it.

Hash lookups still run one process per digest, because Forager takes one digest per
invocation and falls back to an unconstrained PURL fetch when it does not resolve.

### socket.dev

socket.dev sits behind an Anubis proof-of-work challenge. `curl` gets 403 there and
that is not evidence of a block; Forager passes the challenge through `anubis-fetch`
on `PATH`. Check the lane with Forager itself before concluding it is rate limited.

Forager rejects an incomplete reconstruction by default. When a member blob returns 400
the whole package fails rather than yielding a tarball quietly missing a file. Earlier
builds emitted the partial archive under the complete package's name, so treat any
socket.dev sample captured before this behavior landed as suspect and re-verify its
file list. A complete run is fast: roughly thirty seconds per package, not the minutes
a partial run appeared to take.

### Partial reconstructions

`--partial` keeps what a source can still serve. It is worth using because the members
that survive usually include the injected payload: `nextmove-mcp@0.1.7` recovers 9 of
10 members, and the one it loses is not the attack, while the `setup.mjs` named by the
package's `preinstall` hook is present. Without it that incident has no sample at all.

A partial capture is fenced so it can never pass as the published archive:

- the file is named `<package>-<version>-partial.tgz`,
- a `<file>.partial.json` record lists what was listed, recovered, and absent, and
  travels with the bytes exactly as the sidecar does,
- the manifest entry is `verification.status: payload_only` with a note naming the
  absent members,
- `make samples-verify` rejects a partial capture recorded as anything else, and
  rejects one whose accounting record is missing.

Forager still prefers a complete archive. A partial result never ends the fallback
chain; it is held while later sources are tried, the best-recovered capture wins, and
the losers are deleted. An archive where no member could be fetched is not written at
all. Expect partial runs to be slower than strict ones, because every absent member is
retried before it is given up on.

After every run, verify that manifest paths, sizes, hashes, and immutable provenance
sidecars agree:

```sh
node tools/verify-oss-samples.js
```

### Current OSS checkpoint

`OSS_SAMPLE_COVERAGE.yaml` reports 1524 addressable version targets: 92 acquired, 22
comparator-only, 62 unresolved, 628 timed out, and 720 pending. The corpus holds 484
acquired files. Of the 163 reported digests, 39 are acquired.

The pending 720 are almost entirely Packagist, which no run has attempted; read
"Restored distributions" before starting that lane. The 628 timed out are the npm and
PyPI backlog and are the largest recoverable block, bounded only by the socket.dev
rate limit. Work it in bounded batches at low concurrency:

```sh
node tools/acquire-oss-samples.js --fetch --no-before --no-after --partial \
  --batch 25 --concurrency 1 --timeout 900
```

`--only SUBSTRING` restricts a run to one incident directory, which is the quickest way
to revisit a single package after a source comes back.

## Restored distributions

Some coordinates no longer serve the bytes that made them affected. `laravel-lang` is
the clearest case: the attacker rewrote every tag on four repositories, and the
maintainers later restored the pre-attack commits. Packagist resolves all 714 affected
versions today, but it resolves them to the restored objects. Fetching them yields a
comparator, not the during state.

`acquire-oss-samples.js` keeps these incidents in `RESTORED_DISTRIBUTIONS`, which marks
their fetches `classification: clean` so coverage counts them `comparator_only` and no
record claims malicious bytes nobody holds. Add an incident there whenever the current
archive is known to postdate remediation. `intercom/intercom-php` is the same shape:
Packagist resolves the overwritten 5.0.2 to a commit three months older than the attack.

`bfunky/http-parser` is the opposite case and the reason the classification is decided
per version rather than per incident. The package was abandoned, so nobody restored
anything, and Packagist still resolves part of the tag range to the attacker's commits.
Of eight recovered archives, three carried `src/Analytics.php` on 2026 commits and five
resolved to untouched 2016 and 2018 commits. A tag-rewrite incident therefore yields a
mix of malicious and comparator bytes under one coordinate range.

Read a recovered Composer archive before classifying it. The commit date in the zipball
and the presence of the payload file settle it; the incident's affected-version list
does not. Record the commit in the coordinate as `?revision=<sha>` so the exact object
stays attached to the sample. Manifest keys ignore that qualifier, so a later run still
recognizes the sample instead of appending a second copy.

Recovering the real `laravel-lang` during state needs the rewritten commit SHAs, which
the incident record does not yet carry. The most promising source is a contemporaneous
capture of `https://repo.packagist.org/p2/laravel-lang/lang.json`, whose
`dist.reference` fields named the malicious objects while the tags stood. GitHub often
still serves an unreferenced commit by SHA, so recovering the SHAs may be enough.

## Pilot incidents

- `event-stream`: npm carrier versus transitive malicious payload.
- `ultralytics`: multiple PyPI distribution files plus existing extracted evidence.
- `laravel-lang`: a large same-version before/during tag-rewrite problem.
- `wp-blaze-widget`: historical WordPress SVN reconstruction.
- `3cx`: proprietary installers located primarily through hashes and research archives.

## Closed-source acquisition runbook

The proprietary lane is implemented by `tools/acquire-proprietary-samples.js`. It
walks every `proprietary/**/meta.yaml`, extracts each artifact's SHA-256 values and
archive-like URLs, and creates or updates the adjacent `samples/manifest.yaml`. It
uses the same `before/during/after` layout, although the current proprietary pass
only targets `during` artifacts.

### Retrieval order and fallbacks

For an artifact with SHA-256 evidence, the tool invokes Forager with the digest:

```sh
/private/tmp/forager-purl fetch -o <temporary-directory> \
  --hopper http://10.9.8.5:8081 --hash <digest>
```

Forager tries Hopper first, then its configured MalwareBazaar, Triage, Malshare, and
optional VirusTotal providers. Credentials are discovered from the environment or the
operator's private token files (`~/.tok/mbdl`, `~/.tok/triage`, etc.); they must
never be copied into this repository.

Rebuild the binary from the Forager source tree when a lane looks unexpectedly empty;
provider coverage and flag spellings both move:

```sh
make -C ~/dev/atomdrift/forager build test
cp ~/dev/atomdrift/forager/forager /private/tmp/forager-purl
```

VirusTotal downloads are deliberately opt-in because they consume premium quota.
The completed sweep used this explicit final retry:

```sh
FORAGER_VIRUSTOTAL_DOWNLOAD=1 \
node tools/acquire-proprietary-samples.js --fetch --retry --hashes-only \
  --concurrency 16 --timeout 20 --hopper http://10.9.8.5:8081
```

For ordinary vendor URLs, the current Forager build rejects arbitrary URLs as
`unsupported URL`. The proprietary tool therefore tries Forager first, then uses a
bounded `curl -fsSL` fallback. A URL fallback is accepted only when it yields one
non-HTML file; if the artifact has reported hashes, the measured SHA-256 must match
one of them. The fallback writes a local `.forage.json` sidecar with the URL, time,
size, and digest. This prevents an article, VirusTotal GUI page, or vendor download
landing page from being mistaken for a binary sample.

### Useful commands

Inventory only (safe to rerun; refreshes `PROPRIETARY_SAMPLE_COVERAGE.yaml`):

```sh
node tools/acquire-proprietary-samples.js
```

Retry all unresolved targets, including both hash and URL lanes:

```sh
node tools/acquire-proprietary-samples.js --fetch --retry \
  --concurrency 16 --timeout 15 --hopper http://10.9.8.5:8081
```

Retry only distribution and mirror URLs (useful after fixing URL handling):

```sh
node tools/acquire-proprietary-samples.js --fetch --retry --urls-only \
  --concurrency 16 --timeout 10
```

Retry only SHA-256 providers (use this when enabling a new feed or API key):

```sh
node tools/acquire-proprietary-samples.js --fetch --retry --hashes-only \
  --concurrency 16 --timeout 20 --hopper http://10.9.8.5:8081
```

`--retry` is required to revisit an artifact already recorded as unresolved. Use
`--limit N` for a small triage batch. Temporary downloads are removed after they
are either moved into the incident tree or rejected.

### Provenance and validation

Successful files are placed at:

```text
proprietary/<incident>/samples/<artifact-id>/during/<filename>
proprietary/<incident>/samples/<artifact-id>/during/<filename>.forage.json
```

Hash-provider captures retain Forager's sidecar verbatim, including the Hopper or
provider byte URL. The manifest records `verification.status: exact` when the
requested digest equals the measured digest and labels Hopper/API URLs as
`source.kind: research_corpus`. Unsuccessful attempts are retained under the
artifact's `unresolved` entry, including the hashes, candidate locations, provider
errors, and last-attempted time. An artifact is never left silently pending.

The verifier now scans both OSS and proprietary manifests:

```sh
make samples-verify
# equivalent: node tools/verify-oss-samples.js
```

It checks every listed file's SHA-256, size, path containment, and required
provenance sidecar, and rejects unlisted payload files. Do not execute recovered
installers, APKs, scripts, archives, or firmware while triaging them.

### Current checkpoint and resumption

The authoritative checkpoint is `PROPRIETARY_SAMPLE_COVERAGE.yaml`. The last full
pass covered 163 artifact declarations: 55 carry a SHA-256, 88 carry a digest of any
kind, and 67 are URL-backed. It reports 39 artifact declarations covered and 124
unresolved, with 37 sample files on disk; repeated declarations can make the
covered-artifact count larger than the file count.

Widening the hash lane from SHA-256 to every published digest raised the addressable
set from 55 artifacts to 88 and, together with the rebuilt Forager, took proprietary
coverage from 19 to 39. That pass recovered CCleaner 5.33, three SolarWinds Orion
builds, Kaseya VSA, X_Trader, the MEDoc payload, and Passwordstate.

Some historical URLs returned HTML rather than samples. Those bytes were removed
from `samples/`; relevant VSDC pages are retained under `proprietary/vdsc/context/`,
and invalid captures from the latest run were quarantined under
`/private/tmp/proprietary-invalid-captures/` for local inspection. Never promote
those pages without independently locating the actual installer or payload.

To resume, start with the unresolved inventory rather than redownloading successes:

```sh
rg -l 'status: unavailable' proprietary --glob 'samples/manifest.yaml' | sort
node tools/acquire-proprietary-samples.js --fetch --retry --hashes-only --limit 20 \
  --concurrency 4 --timeout 30 --hopper http://10.9.8.5:8081
make samples-verify
```

When a new source is found manually, save the bytes and its source metadata beside
the file, verify the digest before editing the manifest, and record why it is
`exact`, `probable_exact`, `payload_only`, or `unverified`. Keep provider terms,
licensing, and redistribution restrictions attached to the incident notes.
