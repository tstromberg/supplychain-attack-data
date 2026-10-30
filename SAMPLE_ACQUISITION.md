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

Every acquired file is also recorded in `samples/provenance/<sha256>.json`. The record is
capture-time evidence about the *bytes*, which is why it is filed under their digest
rather than beside the file: a sample that is later re-phased or renamed does not drag its
history along, and cannot be separated from it by a rename that fails halfway.

Each record holds a list of acquisitions, because the same bytes are often obtained more
than once — one AUR `.desktop` file arrives byte-identical from nine different commits.
An acquisition states the measured digest and size, requested package identity, successful
byte URL, retrieval time, collector, and any registry or threat-feed record available to
Forager. An acquisition returned by Hopper is preserved verbatim after its artifact digest
is checked; it is never replaced by a new local record. Tools write through
`tools/provenance-store.js` rather than composing the path themselves. The manifest adds incident-level interpretation, source-chain facts,
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

At least one acquisition in the provenance record must repeat the reconstruction chain and
state that its own digest identifies the synthetic container rather than the removed
upstream archive. Verification must compare the reconstructed tree member-for-member
against the retained manifest, including paths, sizes, and content hashes.

### A reconstruction stops being one when the bytes turn out to be the distribution

`RECONSTRUCTED` in a filename, and `tree_equivalent` in a manifest, are claims about
provenance: these members are verified, these archive bytes are not what the registry
served. Both are wrong the moment the published archive is in hand, and the corpus
carried that error in two forms until `node tools/promote-reconstructions.js` went
looking for it.

**Bytes that were the distribution all along.** Three samples were recorded as
`tree_equivalent` while their `source.url` pointed at `repo.huaweicloud.com` — the
published tarball, fetched from a mirror, filed as a rebuild of itself. One of them
carried the reasoning: "the archive container's digest is mirror-specific, so this is
tree-equivalent rather than claimed as the byte-identical npm tarball." That is the
misconception the whole mirror lane rests on being false. A caching proxy serves the
bytes it cached; it does not re-pack an archive. There is no such thing as a
mirror-specific container digest, and those samples are `probable_exact` distributions.

**Bytes a mirror can still supersede.** The rest were genuine socket.dev and jsDelivr
re-packs, made before the mirror lane existed. Asking the mirrors for each one found
the published archive for 65 of them, and in only 3 of 68 did a re-pack happen to
reproduce the published tarball byte for byte — so re-packing almost never lands on the
original, and `reconstructed` is the honest name for the ones that stay. Where the
original came back it replaces the rebuild, and the rebuild is deleted rather than kept
beside it: two near-identical archives, one synthetic, is how a synthetic one ends up
cited as evidence.

What survives the promotion is the per-member evidence. An entry whose basis said
`all_244_members_match_independent_jsdelivr_sha256_inventory` keeps saying it — the
status was wrong, not the verification work behind it — and the correction is written
as a note that names what it supersedes rather than by quietly deleting the old claim.

### Reproduce an existing reconstruction before making a new one

A reconstruction's packaging is as load-bearing as its content: sorted path order and zeroed
timestamps still leave tar framing and gzip settings to choose, and two reasonable choices
give different bytes. Before building a new one, rebuild an existing one from its own recorded
inputs and check the SHA-256 the manifest states. If it does not match, the method differs
from the corpus's, and the new archive would be reconstructed by a rule nobody else can rerun.

For the monkey.org set that took two corrections. The 2002 tarballs use the older AREGTYPE
(NUL) type flag, which has to be written as REGTYPE (`0`), and GNU framing writes `ustar  \0`
where the corpus's archives carry `ustar\000` — each changes the header checksum and so every
byte downstream. With both fixed, `fragroute-1.2-RECONSTRUCTED.tar.gz` rebuilds to
`15127c19...` exactly, and only then is the same recipe worth pointing at another tarball.

### What a reconstruction may not invent

Content and position are separate claims. The monkey.org backdoor block is published in full,
and Dug Song's advisory states the same block went into all three tarballs at 03:00 on
2002-05-17 — which the block itself supports, since it ends with an `eval echo configure:2379`
line that matches none of the three files, the residue of a verbatim paste. That settles what
was inserted. Where it sat is a different question, and it is answerable for one of the two
missing tarballs and not the other:

- `fragrouter-1.6` has the same AC_LBL socket/nsl checks that populate `$LIBS`, which the
  block's own `gcc $LIBS conftest.c` line needs, and the one published position sits
  immediately after them. Two constraints agree, the record says so, and the archive was built.
- `dsniff-2.3` has no such macro at all: its socket and nsl checks belong to AC_PATH_XTRA and
  populate `X_EXTRA_LIBS`, never `$LIBS`. There is no anchor and no published digest, so any
  placement would be invented and none was built.

Record the distinction where a reader will hit it. The reconstruction carries an
`insertion_point` block with `established: false`, the anchor, and the reasoning; the
`verification.basis` names `insertion_point_inferred_not_established`; and the unresolved entry
for the tarball that was not built says why.

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
- Samples are stored uncompressed, under the filename they were distributed with. There
  is no size threshold and no storage container; see "Storage form".

## Storage form

A sample is stored as the bytes that were distributed: real file, original filename, no
container. `sha256` and `size` in the manifest describe those bytes, and `path` names the
file that holds them.

```yaml
  filename: JAVS.Viewer8.Setup_8.3.7.250-1.exe
  path: justice-av-solutions-javs-viewer/during/JAVS.Viewer8.Setup_8.3.7.250-1.exe
  sha256: fe408e2df48237b11cb724fa51b6d5e9c74c8f5d5b2955c22962095c7ed70b2c
  size: 107965976
```

Until 2026-09-11 a sample over 75 MB was held xz-compressed and the manifest carried a
`storage` block describing the container. That existed for one reason: git handles large
binaries poorly and GitHub refuses any blob over 100 MiB. It bought very little even then
-- these are installers and archives, already compressed, so xz took 1,912 MB down to
1,738 MB, about 9% -- and for eight samples it bought nothing, leaving them still over the
limit and excluded from the repository by a `.gitignore` written beside them.

Payload bytes now live in the artifact tree rather than in git, so the ceiling that
justified all of it no longer applies to them. What remained was a second representation
every consumer had to know about, in the middle of a pipeline whose output was
decompressed anyway. `tools/decompress-samples.js` removed the containers, and
`make samples-verify` now rejects a `storage` block outright, so a tool cannot quietly
reintroduce one. An `.xz` file in the corpus is a distribution in its own right -- the
`xzutils` samples are genuinely `.tar.xz` releases -- and is stored and hashed as such.

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
  --hopper http://10.9.8.10:8081
node tools/acquire-oss-samples.js --fetch --before-only --live-only \
  --hopper http://10.9.8.10:8081
```

Reported hashes are a separate evidence lane because a metadata record can contain
several versions and several hashes without defining a mapping between them:

```sh
node tools/acquire-oss-samples.js --fetch --hash-only \
  --hopper http://10.9.8.10:8081
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

### Deleted PyPI releases

PyPI distinguishes three removals, and only one of them is a recovery problem. A
*yanked* release (PEP 592) keeps its files: pip skips it during resolution, but an
exact pin still downloads it. An *archived* project keeps its files too; it is only
hidden from search and closed to new uploads. A *hard-deleted* release — the usual
outcome when PyPI administrators pull malware — is wiped from the CDN, the JSON API,
and the simple index, and the public mirrors follow within a day.

Software Heritage is the lane that survives that. It crawls PyPI on its own schedule
and keeps the sdist tree from whatever visit caught the release, so a version that
stood for a single day can still be there. `mrmustard@0.7.4` is the worked example:
published 2026-07-23, gone from PyPI by 2026-07-25, and archived by a Software
Heritage visit on 2026-07-24 that sits between the two.

Reaching it needs one thing the npm lane did not. Forager now examines **every** full
visit of an origin, newest first, instead of only the most recent: a deleted version is
absent from every later snapshot by definition, so the newest visit is exactly the one
that cannot name it. For mrmustard the current snapshot's HEAD is `releases/0.7.3` and
only the 2026-07-24 snapshot carries `releases/0.7.4`.

### Software Heritage coverage

Every ecosystem Software Heritage lists natively names versions with the same
`releases/<version>` snapshot branch, so one resolver serves all of them and only the
origin URL and archive naming differ. Forager wires the lane for all eight:

| ecosystem | origin URL | rebuilt as |
| --- | --- | --- |
| npm | `https://www.npmjs.com/package/<name>` | `<name>-<version>.tgz`, root `package/` |
| pypi | `https://pypi.org/project/<name>/` | `<name>-<version>.tar.gz` |
| cargo | `https://crates.io/crates/<name>` | `<name>-<version>.crate` |
| rubygems | `https://rubygems.org/gems/<name>` | `<name>-<version>.tar.gz` |
| cran | `https://cran.r-project.org/package=<name>` | `<name>_<version>.tar.gz`, root `<name>/` |
| hackage | `https://hackage.haskell.org/package/<name>` | `<name>-<version>.tar.gz` |
| hex | `https://hex.pm/packages/<name>` | `<name>-<version>.tar.gz` |
| pub | `https://pub.dev/packages/<name>` | `<name>-<version>.tar.gz`, flat |

Two of those are deliberately not given their native extension. A RubyGems `.gem` is a
tar wrapping `data.tar.gz` and `metadata.gz`, and a hex.pm `.tar` wraps
`contents.tar.gz` plus metadata; Software Heritage keeps the unpacked contents rather
than either container, so naming the result `.gem` or `.tar` would claim a structure it
does not have.

Composer is archived through the git commit its Packagist dist is pinned to rather than
by coordinate, and is handled separately. Go modules, NuGet, Conda, and the AUR reach
Software Heritage only through git origins, which carry no version branch to resolve;
Forager refuses those rather than retrying an ecosystem that cannot answer.

Two limits are worth stating plainly. Software Heritage archives the sdist only, never
the wheels, and it stores the source tree rather than the publisher's archive bytes, so
the result is `verification.status: tree_equivalent` and never `exact`. Per-file content
is still exact and can be checked against Software Heritage's own `sha1_git`.

Set a token before a run of any size; anonymous access is rate limited per request and
the walk costs one request per file:

```sh
export SWH_API_TOKEN=$(cat ~/.tok/sher)
```

Sources checked for this lane and found not to hold purged releases: the Datadog
`malicious-software-packages-dataset` (1834 PyPI packages, no mrmustard), piwheels
(which rebuilds its own ARM wheels and had only 0.7.0/0.7.1/0.7.3), and StableBuild's
deleted-package index. They remain worth checking per incident; none is a general
substitute for Software Heritage.

### crates.io mirrors

crates.io deletes a malicious release rather than yanking it, and both the API and
`static.crates.io` then answer 403 for that version. Deletion is also propagated to
the sparse index, so the coordinate stops resolving entirely.

Regional mirrors keep serving tarballs they already hold. Forager's cargo lane
therefore falls back from crates.io to `mirrors.ustc.edu.cn`, `rsproxy.cn`,
`mirrors.aliyun.com`, and `mirror.nju.edu.cn`. They do not hold the same set, and the
order matters less than the count: in the `arrayref` incident USTC served
`arrayref@0.3.10` but 403'd `proc-macro1` entirely, while rsproxy served
`proc-macro1@1.0.107` and 403'd `1.0.106`, which no asked mirror had.

A mirror capture is still `exact` when its digest can be bound to an authoritative
record. The `cksum` for a deleted version survives in the `rust-lang/crates.io-index`
git history even after the version is removed from the current index file:

```sh
gh api "repos/rust-lang/crates.io-index/commits?path=ar/ra/arrayref&until=<date>"
gh api "repos/rust-lang/crates.io-index/contents/ar/ra/arrayref?ref=<sha>" \
  --jq '.content' | base64 -d
```

That history is also the record of what the attacker did to the index: publish times to
the second, and which prior versions were yanked and when.

### Finding the ids a reset removed, with the activity API

The mirror lane below needs a commit id, and for a mass wave nobody publishes one. The
July 2026 AUR wave was recorded as "at least 89 package names publicly corroborated,
community-assembled and still growing", with no ids at all.

GitHub's repository activity API answers this directly. It reports every ref change on a
repository, including force-pushes, with the commit on each side:

```sh
gh api "repos/archlinux/aur/activity?ref=refs/heads/openconnect-sso"
# 2026-07-29T10:26:09Z push        before=c2fc534b3318 after=9d107786fa85
# 2026-07-29T11:00:43Z force_push  before=9d107786fa85 after=c2fc534b3318
gh api --paginate "repos/archlinux/aur/activity?activity_type=force_push&per_page=100"
```

The poisoning and the cleanup, 34 minutes apart, and `before` on the force-push is the id
the mirror still serves. Filtering force-pushes to the wave window enumerated 298 package
branches where the record had 89.

Do not use GH Archive for this. Its PushEvents for the same repository carry `payload.head`,
which looks like the same answer, but the mirror's pushes are aggregated and most never
appear: a full window scan found 277 branches and none of the ones known to be affected.

A window is a candidate list, not a finding — maintainers force-push routinely. Confirm
each against the wave's own signature, and confirm it in the commit rather than in its
metadata, because both the file name and the commit message are chosen to blend in:

- **July 2026**: the commit adds an extensionless binary and its own PKGBUILD invokes it
  as `sudo "$srcdir/<name>"` in `build()`. 290 of 298 matched. All 284 payload copies are
  one 43,640-byte loader under 28 different build-tool names — validator, indexer,
  compressor, parser — under messages like `upgpkg` and `updpkgsums`.
- **June 2026**: no binary at all. The commit adds a `<pkgbase>-deps.install` pacman
  scriptlet whose `post_install()` runs `bun add` or `npm install` against the attacker's
  npm packages, so the payload arrives as root at install time rather than build time.

Where Arch pushed a revert before resetting, the reset removed the revert and the
malicious commit is its parent, so the check walks back a few commits before giving up.

The June scriptlets also have to be de-obfuscated before any of this matches. The later
ones write every identifier as concatenated quoted fragments and escapes:

```sh
"c""d" '/''t'$'\x6d''p' && 'b''u''n' 'a'$'\144''d' 'o'$'\x72'"a" 'n'"e"'x''t'"f"'i'"l"'e'"-"$'\x6a''s'
```

which is `cd /tmp && bun add ora nextfile-js`. Decode `$'\xNN'` and `$'\NNN'`, drop the
quotes, then match. Searching the raw text finds nothing and reports the wave as clean.

### AUR commits the history was reset past

Arch does not revert a malicious AUR commit, it resets the package's history past it.
Afterwards cgit answers 404 for the commit id, `git fetch` of that id is refused with
"not our ref", and Software Heritage has no revision object, which is what the
`openconnect-sso` and `meshcore-open-git` records had concluded.

Arch DevOps also mirrors every AUR repository to `github.com/archlinux/aur`, and GitHub
keeps a commit it has once received after the ref that carried it goes away. The reset
propagates to the mirror's branches, so the commit is not reachable by name — but it is
still addressable by id:

```sh
gh api repos/archlinux/aur/commits/9d107786fa851c6305dadb3573aab5330a041524
node tools/acquire-aur-commit.js --incident arch-aur-august-2026 \
  --artifact openconnect-sso --commit 9d107786fa851c6305dadb3573aab5330a041524
```

That recovered the complete malicious `openconnect-sso` tree, including the 43,640-byte
`validator` whose SHA-256 is exactly the `2d25d2ea...` the tracker published, and the
whole `meshcore-open-git` tree, whose `optimizer` is byte-identical to the copy that had
been recovered separately from Triage.

The tool verifies every file against the git blob id the commit's own tree names. A blob
id is SHA-1 over `blob <size>\0` and the content, so reproducing it proves the bytes are
the ones that commit contained, without trusting the mirror. That check is what makes
these `exact` rather than mirror-sourced, even for the members no report published a
digest for.

The lane needs a commit id, and it is the id that is usually missing. Where a wave is
recorded as a wildcard — 89 corroborated package names in the July 2026 AUR wave, no
published commit ids — the blocker is identifiers, not availability. GH Archive's
PushEvents for `archlinux/aur` over the attack window are the way to recover them.

### Removed npm releases on caching mirrors

npm unpublishes a malicious version outright: `registry.npmjs.org` answers 404 for the
tarball and the version disappears from the packument. The corporate proxies that sit
in front of npm do not re-check. Whatever they cached while the release was live stays
on a public URL, and those are the *published* bytes rather than a re-packing of a CDN
file listing, which is what separates this lane from jsDelivr and socket.dev.

Forager carries this lane, so the ordinary `acquire-oss-samples.js --fetch --ecosystem
npm` run reaches it: when npm no longer serves a version, the mirrors are tried before
any reconstruction, in the order `repo.huaweicloud.com/repository/npm`,
`registry.npmmirror.com`, `r.cnpmjs.org`, `mirrors.cloud.tencent.com/npm`. Huawei
retains the most and is asked first; Tencent answers 451 to whole regions and cannot be
relied on. `node tools/acquire-npm-mirror.js --phase during` (`make samples-npm-mirror`)
sweeps the corpus through the same mirrors directly, which is the faster way to run the
lane alone over every record.

The packument is no guide to what a mirror will serve, so ask for the tarball path
rather than reading the version list: `@antv/adjust@0.4.5` is absent from Huawei's
listing and its tarball still downloads. Mirrors also disagree on layout in the other
ecosystems — a crate is at `/api/v1/crates/<name>/<version>/download` on USTC and
`/crates/<name>/<name>-<version>.crate` on NJU, which serves only the latter — so a
single assumed spelling silently reports live releases as gone.

Nothing is stored until the archive gunzips and its own `package/package.json` names
the coordinate that was asked for. Every one of these hosts answers an upstream miss
with an HTML or JSON body under a 200 at least sometimes, and `github.com/<org>/<repo>/
archive/<sha>.tar.gz` does the same for a repository GitHub has disabled — a 152 KB
"unavailable" page that `file` reports as HTML and `tar` refuses. A downloaded 200 is
never evidence on its own.

A mirror capture is `probable_exact`: original distribution bytes with no authoritative
digest to bind them, unless the record states a SHA-256 that the bytes reproduce. The
run against the 2026 corpus recovered 458 removed releases this way, including 172 of
the @antv packages TeamPCP republished and most of the IronWorm and Red Hat
`@redhat-cloud-services` namespaces.

The same shape applies to the other ecosystems, with different retention. Deleted crates
survive on the regional mirrors and they do not hold the same set — `arrayref@0.3.10`
came from USTC, `proc-macro1@1.0.107` only from rsproxy — so a crate capture is worth
asking every mirror for. PyPI's mirrors are the weak case: they resync rather than only
accumulate, so a deletion propagates, and `ctx`, `ssh-decorate` and `torchtriton` are
absent from tuna, aliyun, Tencent, BFSU and NJU alike. Their simple index is still the
right lane to try, because each entry states the file's own SHA-256 and a hit is
therefore verifiable rather than merely plausible. Go modules barely need this: a proxy
never deletes what it cached, so a miss means no proxy ever saw the module, and the
origin repository is the fallback that matters.

### Two npm takedowns, opposite outcomes

npm removes a package in two ways and only one of them leaves the bytes recoverable.
An **unpublish** drops the versions from `registry.npmjs.org` while the caching mirrors
keep whatever they held, which is the lane above. A **security holding package** replaces
the project with a stub version `0.0.1-security` (`"description": "security holding
package"`, `"repository": "npm/security-holder"`), and the mirrors sync that replacement,
so every real version is gone everywhere and no version number or digest survives to
search on.

Tell them apart before spending time: ask a mirror for the packument and look at the
version list. Real versions mean the unpublish lane may work; a list containing only
`0.0.1-security` means it will not. In `arch-aur-atomic-arch` one campaign used three npm
packages — `js-digest` and `lockfile-js` were unpublished and came back from npmmirror,
while `atomic-lockfile` got a security holder and is unrecoverable.

The stub is still worth collecting, as `verification_material` rather than a phase sample:
its README states the package contained malicious code and was removed by the npm security
team, and its publish timestamp dates the takedown.

A third shape looks like the first and is not: the version is unpublished, the package
survives, and no mirror ever cached that version. `@nrwl/nx@20.9.0`, `@nx/key@3.2.0`,
`@rspack/cli@1.1.7` and the `@react-native-aria` pair are all absent from npm and from
every mirror's version list and tarball path. Nothing distinguishes this from the
recoverable case except asking.

### Resolving an MD5 before searching for it

`forager identify` can only ask MalwareBazaar about an MD5, because Triage and MalShare
index SHA-1 and SHA-256 and not MD5. A record naming only an MD5 is therefore never
searched against the lane that most often pays off. Convert first:

```
curl -H "x-apikey: $(cat ~/.tok/virustotal)" \
     https://www.virustotal.com/api/v3/files/<md5>
```

`data.attributes` carries `sha256`, `sha1`, `size`, `meaningful_name` and
`last_analysis_stats.malicious`. The free key is metadata only — the download endpoint is
refused — so this converts, it does not acquire. Rate limit is four requests a minute;
checkpoint to a file so a crash resumes, and record the answer in the record's `hashes` as
a separate entry with a note, so the lookup is never repeated.

A negative is a finding: an MD5 VirusTotal has never seen is unreachable by every digest
lane, and is either wrong or names a file no public collection holds. Of 54 MD5-only
digests swept in September 2026, VirusTotal knew 18 and had never seen 36.

### Triage matches inside an archive

`forager identify` reports an `Exact` flag per provider. **`Exact: false` from Triage is a
lane, not a miss** — the digest matches a file *inside* a submitted archive rather than a
submitted file. `forager fetch -hash` refuses these, correctly, and reports the digest
unavailable, which reads like a dead end and is not.

Search Triage for the digest, take the sample id whose `filename` is the container, fetch
`https://tria.ge/api/v0/samples/<id>/sample`, and extract. Malware zips there are often
AES-encrypted with the password `infected`, which macOS `unzip` cannot read — use
`7z x -pinfected` — and they nest. The search results frequently also list direct
single-file submissions named by their SHA-256, which need no extraction at all.

This recovered both trojanized VGCA signing-toolkit MSIs with the PhantomNet dropper and
backdoor, and the Energizer DUO installer with Arucer.dll: six samples across two records
that every prior digest lane had reported unavailable.

### Remediated releases are the reliable phase

Nobody takes down the fix. An `after` sample is usually obtainable long after the
malicious release has been purged, because the registry that served the bad version still
serves the good one: crates.io and RubyGems publish a checksum per version, WordPress.org
keeps every version of a theme or plugin including closed ones, GitHub keeps tags and
release assets, Docker Hub resolves a tag to a manifest digest, and the Visual Studio
Marketplace serves a named version for a publisher still in good standing.

`node tools/acquire-wordpress-release.js` runs the WordPress case over the whole corpus.
`node tools/acquire-url-sample.js --expect <sha256>` stores a single artifact from any URL
and refuses to write bytes that do not reproduce the digest given; `--file` stores
already-fetched bytes, for a source needing credentials `curl` is not given.

### A 200 is not the build you asked for

The recurring trap in this phase is a vendor or archive answering at the right URL with
the wrong release. `downloads.wordpress.org` returns 200 for coordinates that do not
exist. The Chrome Web Store served version 11.0.43 against an affected 3.12.3. DAEMON
Tools serves only its current installer, under a fixed filename. The single archived
Comm100 installer declares ProductVersion 11.2.1 against a fixed version of 10.0.9.

So bind on what the artifact says about itself, not on where it came from: a WordPress
theme declares its version in `style.css` and a plugin in its readme's `Stable tag`, a
VSIX in `extension/package.json`, an npm archive in `package/package.json`, a source
tarball in its top-level directory name, and a Windows installer in its PE version
resource. `acquire-wordpress-release.js` refuses any archive that does not declare the
version the record names.

Two cases deserve their own answer rather than a stored file. A package rebuilt by another
vendor is not the artifact: CentOS vault serves both fixed Red Hat OpenSSH NEVRAs, but as
CentOS rebuilds signed with a different key, so they are recorded and not stored. And a
`fixed_versions` that no registry has ever served is a metadata error rather than a gap —
`flatmap-stream` claimed a fix of 0.1.2 that never existed, where the real remediation was
`event-stream@4.0.0` dropping the dependency.

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

A purged CDN is the case that made partial runs look unusable. jsDelivr keeps a
package's file listing after the bytes are gone, so every member 404s, the archive is
rejected at the end anyway, and the walk costs one paced request per file: 57 members
of `js-digest@4.2.2` took over ten minutes to produce nothing, and a batch of npm
targets could sit on a single package for a quarter of an hour. Forager now abandons a
partial reconstruction once three members have failed with nothing recovered
(`purgedListingRun` in `pkg/registry/archive.go`); a store that holds any of the package
answers well before that. The same run then finished in about a minute and reached
socket.dev, which had 55 of the 57 members.

After every run, verify that manifest paths, sizes, hashes, and immutable provenance
sidecars agree:

```sh
node tools/verify-oss-samples.js
```

### Current OSS checkpoint

Every one of the 187 open-source incidents has at least one `during` sample on disk, and
all 187 hold recovered bytes rather than an evidence record.

`OSS_SAMPLE_COVERAGE.yaml` reports 2299 addressable version targets: 634 acquired, 719
comparator-only, 151 unresolved, 80 timed out, and 715 pending. The corpus holds 2573
files across 187 manifests — 2260 `during`, 207 `before`, 106 `after`.

The pending 713 are almost entirely Packagist, which no run has attempted; read
"Restored distributions" before starting that lane. Work the npm and PyPI backlog in
bounded batches at low concurrency:

```sh
node tools/acquire-oss-samples.js --fetch --no-before --no-after --partial \
  --batch 25 --concurrency 1 --timeout 900
```

`--only SUBSTRING` restricts a run to one incident directory, which is the quickest way
to revisit a single package after a source comes back.

`redhat-cloud-services` is the largest unfinished single incident: 96 removed npm
versions across 32 packages, of which 5 are captured. socket.dev has them and serves
one file at a time, so the lane is bounded by wall-clock rather than availability.

The last nineteen incidents without a `during` sample were closed by hand rather than by
a run; what worked is written up under "When every automated lane fails" below. Three
remain genuinely unrecoverable and say so in their manifests: the phpMyAdmin 3.5.2.2
mirror ZIP, the two trojanized Cemu archives (though the payload inside them was
recovered), and Thompson's `cc`, which was never distributed at all.

## When every automated lane fails

Forager's chain answers the ecosystem question: who still serves this coordinate. For
an incident where nobody does, the next question is different — who still holds these
*bytes*, under any name — and it is answered by hand. The sweep that closed the last 19
open-source incidents without a `during` sample used these, roughly in yield order.

**Immutable git objects.** Where the affected distribution was a repository rather than
a release, the object usually survives even when the branch does not. `php-src`,
`reworm`, `kubernetes-el`, and the ForceMemo repositories all still serve their
malicious commits by SHA. Take the blob at the commit
(`raw.githubusercontent.com/<repo>/<sha>/<path>`) as the artifact and the commit as its
binding; that is `verification.status: exact` on `immutable_git_revision`. When
`github.com/<repo>/commit/<sha>.patch` 404s because no branch references the object any
more, the API still returns it with `Accept: application/vnd.github.patch`.

**Payload digests rather than container digests.** A report often publishes both, and
they do not have the same survival odds. None of the configured providers had either
trojanized Cemu archive, but Triage had `startup.pyz`, the payload extracted from inside
the AppImage, under the digest Datadog published for it. Submit every digest a report
prints, not only the ones attached to the artifact you first wanted.

**SHA-1, not just SHA-256.** MalwareBazaar and Triage index all three algorithms, and
older incidents were frequently reported with SHA-1 alone. The fractureiser Dungeonz jar
came back on the SHA-1 the investigation team published.

**Public research corpora.** Several hold real bytes and are worth checking by package
name before concluding a removed release is gone:

| corpus | holds | note |
| --- | --- | --- |
| `lxyeternal/pypi_malregistry` | PyPI packages, by name and version | ~750 MB; yielded `yocolor@0.4.6` for `top-gg` |
| `DataDog/malicious-software-packages-dataset` | 1834 PyPI packages | `samples/pypi/manifest.json` lists them |
| `fractureiser-investigation/fractureiser` | decompiled stages, affected-mod table with hashes | no jars, but the hashes feed the digest lanes |
| Backstabber's Knife Collection | index only on GitHub | `data/packages.json` is a name index; the corpus is by request |
| `KTH-LangSec/nodeshield` | harnesses, not packages | its `index.js` files name each sample's trigger |

Backstabber's and NodeShield are worth checking even though neither ships bytes: they
tell you the sample exists somewhere, which belongs in the unresolved record, and
NodeShield's harness disclosed the magic key `gfaffhaai` that `getcookies` responded to.

**GitHub code search for a campaign marker.** ForceMemo's shared variable name
`lzcdrtfxyqiplpd` still returns 227 live hits, which is how three infected repositories
were sampled directly rather than through a report. Search for the marker the report
names, and for the reported digest itself — that finds the IOC repositories that
mirrored the report, which sometimes carry its full text when the vendor blocks
retrieval.

**The report as a reconstruction input.** When the bytes are provably gone, the excerpt
a researcher printed is often the only surviving copy of the malicious content, and
"Partial reconstruction inputs" above governs it. Two rules did the work here. Keep the
report's own line wrapping when it wrapped mid-token, because a PDF cannot distinguish
that from significant whitespace — the poisoned BdThemes `display_id` is stored wrapped
for that reason. And derive further only where the derivation is total: decoding a
`String.fromCharCode` list consumes nothing but digits, so the decoded stage-1 fetch is
exact regardless of how the page broke the lines.

**Archived captures need their encoding recorded.** `web.archive.org/web/<ts>id_/<url>`
replays the original bytes, which for a compressed response is the gzip container. Fetch
with `curl --compressed` and record the decode as a derivation step; otherwise the
manifest digest describes a container the sidecar does not mention.

**Say what is withheld, not only what is missing.** The reporter's copy of the
compromised Monero wallet still exists on Google Drive; Google answers "Only the owner
is allowed to download infected files". That page is worth capturing. An artifact with a
known holder and a policy block is a different unresolved record from one nobody has.

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
  --hopper http://10.9.8.10:8081 --hash <digest>
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
  --concurrency 16 --timeout 20 --hopper http://10.9.8.10:8081
```

For ordinary vendor URLs, the current Forager build rejects arbitrary URLs as
`unsupported URL`. The proprietary tool therefore tries Forager first, then uses a
bounded `curl -fsSL` fallback. A URL fallback is accepted only when it yields one
non-HTML file; if the artifact has reported hashes, the measured SHA-256 must match
one of them. The fallback records an acquisition with the URL, time, size, and digest. This prevents an article, VirusTotal GUI page, or vendor download
landing page from being mistaken for a binary sample.

### Useful commands

Inventory only (safe to rerun; refreshes `PROPRIETARY_SAMPLE_COVERAGE.yaml`):

```sh
node tools/acquire-proprietary-samples.js
```

Retry all unresolved targets, including both hash and URL lanes:

```sh
node tools/acquire-proprietary-samples.js --fetch --retry \
  --concurrency 16 --timeout 15 --hopper http://10.9.8.10:8081
```

Retry only distribution and mirror URLs (useful after fixing URL handling):

```sh
node tools/acquire-proprietary-samples.js --fetch --retry --urls-only \
  --concurrency 16 --timeout 10
```

Retry only SHA-256 providers (use this when enabling a new feed or API key):

```sh
node tools/acquire-proprietary-samples.js --fetch --retry --hashes-only \
  --concurrency 16 --timeout 20 --hopper http://10.9.8.10:8081
```

`--retry` is required to revisit an artifact already recorded as unresolved. Use
`--limit N` for a small triage batch. Temporary downloads are removed after they
are either moved into the incident tree or rejected.

### Provenance and validation

Successful files are placed at:

```text
proprietary/<incident>/samples/<artifact-id>/during/<filename>
proprietary/<incident>/samples/provenance/<sha256>.json
```

Hash-provider captures retain Forager's record verbatim, including the Hopper or
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

### Mutable URLs and the window diff

An installer has a version; a CDN script does not. For `trackpoint-async.js`,
`counter.js`, or any other URL a vendor overwrites in place, the artifact is whatever the
host returned at a moment in time, and the incident window is the only coordinate there
is. `tools/wayback-window-diff.js` turns that into a procedure:

```sh
node tools/wayback-window-diff.js --url https://www.statcounter.com/counter/counter.js \
  --from 20181103 --to 20181106 --before 20181001 --after 20181201
```

It fetches a capture from before the window and one from after, then every distinct
capture inside it, and reports which ones match neither baseline. The tampered copy
identifies itself: it is the one that differs, and the tool prints where it starts to
differ so the injection can be read directly.

Two properties make the result strong enough to record as `probable_exact` without
leaning on any report. When the two baselines are byte-identical to each other, the file
was otherwise stable across the window, so a difference inside it is the incident and
not a routine release. And when the tampered capture *begins with* the clean file byte
for byte, the attack appended rather than rewrote, which is worth stating in the manifest
because it makes the payload a clean byte range rather than a judgement call.

This recovered three incidents that were recorded as having no obtainable artifact:

| incident | what the archive held |
| --- | --- |
| `statcounter` | the injected `counter.js`, 574 bytes longer than the clean file, checking for `myaccount/withdraw/BTC` |
| `adform` | three tampered `trackpoint-async.js`, growing 2174 → 3610 → 6945 bytes in two hours |
| `apifox` | the tracking script with 40332 bytes appended, its clean 37859-byte prefix intact |

`adform`'s meta.yaml said no archived copy had been located; three were. Search before
recording a negative, and re-check a negative that predates a tool.

Read a payload's own decoder rather than running it. All three injections carry their
string constants encoded, and in two cases the decoding is total: the Adform payload
XORs against a key declared beside the literals, and the StatCounter one uses the
standard `p,a,c,k,e,r` dictionary. Applying the substitution to the literals is
arithmetic, not execution, and it produced the three attacker wallets from Adform and the
`statconuter.com` second-stage host from StatCounter. Where the transform is not total —
Apifox's rotated string array — say so and stop.

`tools/acquire-proprietary-samples.js` now runs the same lane automatically after the
live URL fails, and it is deliberately stricter than the manual tool: without a reported
digest it accepts only a capture from inside the incident window, because an outside
capture is a comparator and nothing binds it to the attack.

### A placeholder is not an acquisition

The closed-source lane reported full coverage — 163 of 163 artifacts acquired — while
117 of its 165 samples were `metadata_backed_evidence_record` files generated from the
incident's own `meta.yaml`. Those records say plainly that they are "not a recovered
payload", but both the queue filter and the coverage counter asked only whether a
`during` sample existed, so every artifact looked done and no run ever attempted one
again.

`isAcquired()` now excludes them in both places. The honest count was 48 acquired and 115
unresolved, and the lane started returning results the same day: CPU-Z 2.19 and three
Procolored printer bundles from the hash providers, and the Wayback lane above.

The general rule: a record that stands in for a sample must never satisfy the check for
having one. When a placeholder is added to keep a slot occupied, give it a marker the
tooling filters on, and filter on it everywhere the tooling asks "do we have this yet".

### A clean file is never a `during` sample

The same failure in a second disguise. 756 samples sat under `during` carrying
`classification: clean`, and the coverage counter accepted them, so artifacts reported as
covered when the malicious bytes had never been obtained.

Both were produced by fetching an affected version's *coordinate* and storing whatever the
registry returned. An attack that re-tagged existing releases leaves the registry serving
the restored pre-attack commit for an affected version, which is what `laravel-lang`'s 693
files are. An attack that only touched the vendor's own download site leaves the registry
copy of the same version clean: `accesspress` is that case, where Jetpack reported the
WordPress.org releases clean while accesspressthemes.com served backdoored ZIPs. Neither
file is junk — both are the unmodified artifact, which is what `before` means — so
`node tools/rephase-clean-during.js` moves them rather than deleting them.

`tools/verify-oss-samples.js` now rejects a `during` entry whose `classification` is
`clean` or whose `source.kind` is `clean_comparator_distribution`, so it cannot recur.

Note the consequence for a whole record: where the compromise was at the vendor's own site
and the registry copy stayed clean, the registry can *never* supply a `during` sample for
any artifact in that record — only a comparator. For `accesspress` that closes 40
artifacts at once, and fetching those 62 WordPress.org ZIPs would have rebuilt the same
error at scale.

### One artifact, several digests

The closed-source tool's unit is the artifact declaration, and an artifact routinely
declares more than one digest: a Windows build and a macOS build, an installer and the
payload inside it, three versions of the same trojanized package. The queue filter and
the in-run skip both asked whether the artifact had *a* sample, so the first digest
acquired retired the whole declaration and the rest were never requested — 44 targets
became 16, and the missing 28 were not misses but questions never asked.

Both now compare the set of reported digests against the set already on disk, the digest
loop skips only digests it already has, and a run that recovers some but not all of them
records the successes and leaves the unresolved record standing to describe the rest.
Clearing that record on a partial success would discard its accumulated attempt history,
which is the part that tells the next operator what has already been ruled out.

The same pass fixed a crash that had been latent because nothing had ever crossed the
threshold: `record()` compressed samples over 75 MB and then read the pre-compression
path to check the reported digest, so the first 80 MB artifact — EmEditor — took down the
whole run with `ENOENT`. The digest is now measured before compression.

### A wrong digest looks exactly like a missing file

`num2words` was written off as unrecoverable. PyPI had hard-deleted 0.5.15 and 0.5.16, the
Aliyun and Tsinghua mirrors held nothing, Software Heritage had not archived either version
across five snapshots, and the hash providers returned nothing for the two SHA-256 values
the record carried. Every lane said no.

The two digests were wrong. Neither MAL-2025-6794 nor PYSEC-2025-72 contains a digest at
all, so the values attributed to them had no source, and neither matched any file PyPI
served. Every hash lookup ever run for this incident asked for bytes that do not exist,
and got the same answer a genuinely missing file would give.

The correct digests came from DataDog's `malicious-software-packages-dataset`, which
stores each sample beside `package_info-<name>-<version>.json` — the PyPI JSON API
response captured while the release was still live, carrying every file's name, size,
upload time, and SHA-256. With those four values, Hopper returned all four files on the
first attempt: two sdists and two wheels, `exact`.

Three things generalise from it:

- **A negative result is only as good as the identifier behind it.** Before recording an
  artifact as unavailable, check that the digest resolves to something — that some source
  independently associates it with a filename and a size. A digest no one can corroborate
  is not evidence, and searching for it produces a confident, wrong negative.
- **Verify a cited digest against the cited source.** Both of these were attributed to an
  advisory that contains no digests. That is checkable in one request.
- **A malware dataset is worth reading even when it holds no bytes you want.** What was
  useful here was not DataDog's copy of the package — the original distribution files are
  strictly better — but the registry metadata it captured alongside, which is the only
  surviving record of what PyPI published.

The payload, once the files were in hand: thirteen lines appended to
`num2words/__init__.py` that hand `num2words/_build.py` to `ctypes.CDLL` on Windows, where
`_build.py` is not Python but a 1.3 MB PE DLL wearing a `.py` extension so it travels
inside a source distribution unremarked.

### Corroborate a digest before believing a negative

The `num2words` lesson generalises, and the closed-source corpus is where it bites
hardest. Before recording an artifact unavailable, ask whether its digest corresponds to
a file anyone has ever seen. That is a lookup, not a download, and Forager does it:

```sh
forager identify 59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983
forager identify --json <digest> [digest...]      # one JSON object per digest
```

`tools/corroborate-digests.js` drives it across the corpus, walking every record,
skipping digests already satisfied by a file on disk, and reporting each answer against
the artifact that cited it.

The feeds do not index the same algorithms, which is why each is asked only for what it
can answer — a "not found" from a feed that never indexed the algorithm is
indistinguishable from a real miss, and that confusion is the whole problem:

| feed | MD5 | SHA-1 | SHA-256 | catalogue |
| --- | --- | --- | --- | --- |
| MalwareBazaar `get_info` | yes | no | yes | malware samples |
| Triage search | no | yes | yes | sandbox analyses |
| ReversingLabs Spectra Assure Community | no | no | yes | open-source package registries |
| VirusTotal | yes | yes | yes | everything, 500 lookups a day |

MalwareBazaar and Triage cover MD5 and SHA-1 between them, so the quota-limited feed is
not needed for routine work and `forager identify` does not call it.

**Catalogue matters as much as algorithm.** Spectra Assure Community answers only for
open-source package registries, so a miss on a vendor installer, a firmware image or a
browser extension is not evidence of anything — it is out of scope. Against a registry
artifact it is the strongest witness available, because it answers with the coordinate
including the artifact filename and its own malware verdict:

```text
known  d31480b0…  exact  pkg:pypi/num2words@0.5.15?artifact=num2words-0.5.15.tar.gz  [reversinglabs]
known  7e04cda1…  exact  pkg:pypi/yocolor@0.4.6?artifact=yocolor-0.4.6.tar.gz (assessed malicious)
```

That is a third independent confirmation of the `num2words` recovery, arrived at without
the DataDog capture that produced the digest in the first place. It also has a useful
negative: our own socket.dev reconstruction of `js-digest@4.2.2` is unknown to it, which
is correct — that archive was assembled here and no registry ever served it.

One caveat inherited from how the endpoint works: a SHA-256 search returns the *package*
containing the digest, not the file. `7883bda1…`, the `lib/install-deps.mjs` payload named
by an OSSF indicator, comes back as `pkg:npm/js-digest@4.2.2` with no `?artifact=`
qualifier. That corroborates the digest and the package; it does not by itself say whether
the digest names the archive or a file inside it.

**Exact and candidate are different answers.** MalwareBazaar rejects a sample whose own
digests do not include the one asked for, so its hits are confirmed. Triage answers an
MD5 or SHA-1 out of its analysis index, which can match a report that merely *mentions*
the digest, so those are candidates. The distinction is not academic: of 22 bridged
candidates, fetching the bytes and re-measuring the cited digest confirmed 10 and
rejected 5, and the five rejects were all archives whose reports listed the hash —
`Proton.C.zip` came back for four unrelated Elmedia digests at once. Never record a
candidate as the artifact until the bytes measure back.

`3cx` is the case that started this. All four installer digests it carried — two Windows,
two macOS — are unknown to every feed, for one of the most analysed supply-chain incidents
there has ever been, while every digest in the same record that corresponds to a real
artifact is known to both. Asking MalwareBazaar what it *did* have produced
`59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983`:
`3CXDesktopApp-18.12.416.msi`, 102555648 bytes, which Hopper then served.

Confirming it is the trojanized build took no trust at all. Its MSI summary stream names
3CX Ltd. and a 2023-03-13 build date, and extracting its CAB yields `ffmpeg.dll` and
`d3dcompiler_47.dll` byte-identical to the two components already held. A container that
demonstrably contains the known payload is better evidence than any reported digest.

The uncorroborated values are not deleted. They are kept in `meta.yaml` annotated as
unverifiable, with what was checked, because a wrong digest that quietly disappears is
how the next person repeats the search.

**The bridge.** Hopper is SHA-256 only, so an artifact whose record cites only an MD5 or
SHA-1 can never reach the richest source in the chain until a feed resolves it. That
resolution is the second half of what `forager identify` is for.

It recovered thirteen files across two passes, all from records carrying no SHA-256 at
all: three Able Desktop artifacts including the 41 MB trojanized installer, the eWON
eGrabit installer from the Dragonfly/Havex campaign, three DAEMON Tools builds, Fantasy
Agrius, Infestation, the JAVS `fffmpeg.exe`, the NetSarang Xmanager installer, and all
three NoxPlayer update variants. Four of those incidents had never held anything but a
placeholder.

Recording the resolutions matters as much as using them: `with_sha256` went from 65
artifacts to 84, so nineteen artifacts that no SHA-256-only lane could previously address
are now addressable whether or not anyone serves them today.

**Write the resolved digest back.** A lookup that is not recorded has to be repeated. Every SHA-256 the bridge resolves belongs in the
artifact's `hashes` as a `sha256` entry whose `note` names the MD5 or SHA-1 it came from,
what VirusTotal reports as the filename and size, and whether the file is now held. Record whether the resolution was confirmed by measurement or is still a candidate.

Attach them to the artifact, not to the incident. Several artifact ids equal their
incident id, and an edit keyed on `- id: <name>` will match the incident's own line first
and hang the digests off the wrong object, where the tooling will not see them.

One caution learned the hard way: the skip test that decides whether an artifact is
already held compared reported digests against the SHA-256 of files on disk, so a record
citing an MD5 or SHA-1 never matched its own sample and was re-fetched on every run —
overwriting curated filenames with the provider's each time. `existingHashes()` now
measures MD5 and SHA-1 of the held files too, which took the retry queue from 44 to 35.

### A missing identifier is a research gap, not an availability one

Seven of the eight browser-extension incidents recorded no Chrome Web Store id at all.
That is not a hard case; it is an unasked question, because without an id no archive can
be queried even in principle, and the record reads as "unavailable" when nothing was ever
tried.

Five were recovered from references already retained under `refs/`. The
BleepingComputer campaign write-up links each hijacked extension by its Web Store URL, and
Copyfish's own vendor post links its listing, so the ids came out of the corpus rather
than from memory. Three of the five are corroborated a second way, by resolving the id to
a listing title on crx4chrome; the other two are delisted, which is itself consistent with
a removed extension.

With an id, crx4chrome's archived version history becomes askable, and for Chrometana it
answers: it holds v1.1.3 — the hijacked version BleepingComputer names — as a 41.65 KB
file with an MD5 and a SHA-1. The CRX is no longer downloadable there and no feed holds
either digest, so the artifact is still missing; but it went from having no identifier to
having two, which is what a later recovery would be verified against.

For the other four the history either skips the hijacked version or the listing is gone.
`stylish` and `web-developer` still have no id in any retained reference and are the
remaining gap in that group.

### An identifier that names the wrong thing

A digest is not the only identifier a record can get wrong, and the others fail the same
silent way: every lookup answers honestly about something that is not the artifact.

`mega-chrome` carried the Chrome Web Store id `nlbmnnijcnlegkjjpcfjclmcfggfefdm` under a
`/detail/mega/` URL. That id is MyEtherWallet CX. MEGA's is
`bigefpfhnfcobdlfbedofhhaibnlghod`. The mix-up is an easy one — the MEGA payload targeted
MyEtherWallet credentials, so the two names sit together in every write-up of the incident
— but they are different listings, and an archive asked about the first will never answer
about the second.

Resolving an id to a listing is one request, which is the same cheap check as resolving a
digest to a file:

```sh
curl -s -A Mozilla/5.0 https://www.crx4chrome.com/extensions/<id>/ | grep -o '<title>[^<]*'
```

The correction did not produce the artifact: crx4chrome's version history for MEGA stops
at 3.36.0, and 3.39.4 stood for about four hours in 2018 before Google pulled it. But the
record now asks the right question, and its unresolved entry says what was checked with
the right id rather than leaving a future operator to repeat a search that was never
looking at MEGA at all.

### Keep the unresolved records honest

An unresolved record is a claim about the present, and two failure modes make it lie.

**It can understate what is known.** A corroboration sweep produces exactly the fact an
unresolved record should carry: whether the digest names a real file. Those results were
written back into the records they came from, 254 of them across 53 manifests, as an
attempt line naming the feed, what it calls the file, and its verdict where it has one.
The record then says "a real file nobody will serve" rather than an undifferentiated
"unavailable", and the next operator does not repeat the lookup.

**It can outlive the search.** When every digest a record cites is satisfied by a file in
the same manifest, that record is describing a search that finished, and leaving it in
place reads as an open gap. Fifteen such records were removed. The test has to be exactly
that strict: an artifact where some digests are held and others are not is a partial
recovery, and its record is still true — `3cx` holds the Windows installer and the macOS
component while both macOS installers remain missing, and `buddyboss` holds the two
backdoored files while neither update package is recoverable. Those records stay.

### An artifact with no state to collect

`make missing-during` counts an attack covered only when every artifact its record names
has a `during` sample, which is right for a work queue and wrong for the artifacts that
can never have one. Two shapes recur. A runtime-poisoning incident names the packages
that consumed the poisoned feed even though no release of them was ever malicious:
`bdthemes` is seven WordPress plugins whose source never changed, with the attack held
in the one `biggopti-api-feed` artifact. And an incident can be real but unidentified:
no public source names the update files swapped on Blade Chronicle in 2014 or publishes
a digest for them, so no bytes can be recognised as the affected ones.

Both are stated in the record, on the artifact, as `during_sample_not_expected` with the
reason as its value. The report reads that field and lists those artifacts separately
instead of counting them missing. It is deliberately not inferred from an absent version
list — an artifact with no versions is usually a research gap, and inferring would hide
exactly the entries the report exists to surface.

Establishing it is research, not bookkeeping. The `essential-plugin` portfolio was
recorded as thirty-one backdoored plugins; reading every WordPress.org SVN tag of all
thirty-one and testing `wpos-analytics/includes/class-anylc-admin.php` for the backdoor
showed twenty-two shipped it and nine never did. That produced the affected version
lists the acquisition lane needed, corrected the record, and moved the other nine here
with a reason.

### Digests that hide in indicators

`hashes` is not the only place a record puts a SHA-256. A `file_sha256` indicator names
a file *inside* the distributed artifact, written as `"<path> <digest>"`:

```yaml
indicators:
  - kind: file_sha256
    value: bp-loader.php ddda12b545a7b817883641421cf6a213f4c5100effa40cdb55018efce11bbe42
```

Neither acquisition tool read `indicators`, so 96 digests across the two corpora — 76 of
them with no bytes on disk — were never asked about by anything. BuddyBoss is the clearest
case: its two artifacts declare no `hashes` at all, so the incident could never be
anything but a placeholder, while both backdoored files sat in Hopper the whole time.

`memberDigests()` now collects them as a separate target class, and the distinction is
carried through to the record rather than flattened. A member is not the distribution:
it is stored with `classification: malicious` and `verification.status: payload_only`,
carries a note naming the file it came from, and — this is the part worth insisting on —
does **not** retire the container's unresolved record. Recovering `bp-loader.php` says
nothing about whether anyone still has the BuddyBoss Platform update ZIP.

Members are also named after the member when the provider stored the file unnamed, so the
tree reads as `environmentAuthChecker.js` rather than a 64-character digest.

The yield is modest and worth having: of the 76, Hopper holds 4. The point is that they
were previously unreachable rather than unavailable, and the next provider to ingest one
will now be asked.

### Searching the repositories by campaign, not by digest

Forager's hash lane asks a precise question — does anyone hold *these bytes* — and a
repository that has never seen that exact file answers no. That is the right question
for a container the incident record identifies, and the wrong one for an incident whose
artifact was disassembled before anyone submitted it.

MalwareBazaar's `get_taginfo` asks the loose question instead:

```sh
curl -s -H "Auth-Key: $(cat ~/.tok/mbdl)" \
  -d "query=get_taginfo&tag=3CX&limit=100" https://mb-api.abuse.ch/api/v1/
```

For `3cx` that returns five samples. None is either signed installer, and the exact-digest
lane had already failed on all four reported digests — but three of the five are the
attack: the trojanized `ffmpeg.dll`, the `d3dcompiler_47.dll` carrying the appended
encrypted shellcode, and the third-stage stealer. The incident went from a placeholder to
three exact samples, and the installers stay unresolved, which is the truthful shape.

Triage answers the same kind of question through `family:` (`/api/v0/search?query=family:xred`);
`filename:` is indexed far less completely, so a miss there is not evidence.

Both lanes need care when recording. A campaign search returns files *related to* the
incident, not the artifact the record names, so classify what was actually recovered —
a component or a stage, with a note saying the container is still missing — and never
let it close out the unresolved record for the container.

### Current checkpoint and resumption

The authoritative checkpoint is `PROPRIETARY_SAMPLE_COVERAGE.yaml`. It covers 166
artifact declarations: 84 carry a SHA-256, 105 carry a digest of any kind, and 68 are
URL-backed. It reports 68 acquired and 97 unresolved artifacts, and separately 116
recovered `during` samples of which 89 are `exact`, alongside 95 remaining evidence
records.

Read the artifact and file counts together, because they move independently: the
2026-09-02 passes took `recovered_samples` from 48 to 116 while `acquired` moved from 48
to 68, because most recovered files landed on artifacts that already held one. An
artifact-only count would have reported most of that as nothing.

Read `acquired` with the placeholder problem above in mind, too: before `isAcquired()`,
the same report said 163 acquired and 0 unresolved. The number went down because it
became true.

Of the 107 incidents, 45 hold recovered `during` bytes, 56 hold only a metadata-backed
evidence record, and 6 hold neither — five of those six are campaign records that declare
no artifacts of their own, and the sixth, `aiming-blade-chronicle`, has no filename or
digest published anywhere, which its manifest states rather than filling the slot.

**Where the remaining digests stand.** Of 286 closed-source digests not already satisfied
on disk, the feeds recognise 29 — 28 through Triage, one through MalwareBazaar — and have
never seen 257. That second number is the real queue, and it is not one problem: some are
digests of files nobody submitted, and some — as `3cx` and `num2words` both turned out to
be — are digests of nothing at all. Sorting those two cases apart needs the
artifact-specific work described above, not another sweep.

The open-source side answers much better, because Spectra Assure is in scope there. Of 360
open-source digests not on disk, 84 are recognised, 83 of them by Spectra, and seven come
back assessed malicious. Each of those 84 is a reported digest now known to name a real
published artifact, which moves it from "possibly a wrong digest" to "a real file nobody
will serve" — a different problem with different next steps. Regenerate that split with:

```sh
node tools/corroborate-digests.js --scope oss --out /tmp/corroborate-oss.json
node tools/corroborate-digests.js --scope proprietary --out /tmp/corroborate-prop.json
```

Those 56 evidence-only incidents are the work queue, and they are not one problem. Roughly:
the extension incidents need a CRX archive; the firmware and phone incidents (`coolpad`,
`star-n9500`, `gigaset`, `shibai-phones`) need an image nobody publishes; and the Chrome
and CDN JavaScript incidents are candidates for the window diff, whenever the Archive holds
a capture inside the window.

The Magento license-backdoor group is worked out and worth reading as the pattern for the
rest. Every download URL is dead — 403 from Tigren, 404 from Meetanshi and MageSolution —
and the Archive captured none of them, so no ZIP is coming. What Sansec published instead
is the mechanism: `registration.php` includes a `License.php` the module ships, and
`adminLoadLicense` hands the licence file to `include_once`, which executes it as PHP. That
is retained per vendor as a `payload_only` fragment, and the unresolved record states the
structural test a candidate ZIP would have to pass. `fishpig` is the same shape with a
second stage: the backdoor curls `lic.png` from the vendor's own licence host, runs it as
`lic.bin`, and deletes it. The Archive crawled that path once, in 2024, and got a 404. The
family is named — Rekoobe — and that is deliberately not treated as a substitute: any
Rekoobe sample not tied to this campaign would be a guess wearing an artifact's clothes.

To resume, start with the unresolved inventory rather than redownloading successes:

```sh
rg -l 'status: unavailable' proprietary --glob 'samples/manifest.yaml' | sort
node tools/acquire-proprietary-samples.js --fetch --retry --hashes-only \
  --concurrency 4 --timeout 30
node tools/acquire-proprietary-samples.js --fetch --retry --urls-only \
  --concurrency 3 --timeout 30
make samples-verify
```

Hopper moved to `10.9.8.10:8081`; the old `10.9.8.5` address answers `connection
refused`, and every retry against a dead address costs the full per-target timeout, so a
stale `--hopper` is worse than passing none. It authenticates with a bearer token that
Forager resolves from `$HOPPER_TOKEN` or `~/.tok/hopper`.

Its two API routes fail differently, which matters when reading a miss:
`/api/provenance/<sha256>` returning 404 or 204 says only that Hopper holds no provenance
record for the digest, while `/api/file/<sha256>` is the route that says whether it holds
the bytes. Probing the file route directly is also the fastest way to plan a run — every
reported digest in both corpora can be checked in a couple of minutes, which is far
cheaper than discovering the same answers through the full pipeline:

```sh
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $(cat ~/.tok/hopper)" \
  http://10.9.8.10:8081/api/file/<sha256>
```

VirusTotal's download endpoint answers 403 without a Premium/Intelligence key, so
`FORAGER_VIRUSTOTAL_DOWNLOAD=1` adds an attempt and no coverage on the current
credentials.

When a new source is found manually, save the bytes and its source metadata beside
the file, verify the digest before editing the manifest, and record why it is
`exact`, `probable_exact`, `payload_only`, or `unverified`. Keep provider terms,
licensing, and redistribution restrictions attached to the incident notes.

## Auditing the records

The `yaml2csv` validator checks shape — enum values, story structure, required fields — and
running it is the cheapest correctness pass there is. It should report nothing; three
long-standing failures were cleared on 2026-09-02, and two of them were the same kind of
mistake: `crowdstrike-npm` and `sendmail` had grown past the four-paragraph story limit
because acquisition notes were being written into the narrative. Those notes belong in the
sample manifest, which is where they now live.

Some faults the validator cannot see, and they are worth sweeping for periodically:

- **A digest listed twice on one artifact.** Usually the result of a bulk edit appending a
  value the record already had. Deduplicate by digest and keep the annotated entry, not the
  bare one.
- **A digest shared by two incidents.** Coherent only if it names a payload both carried,
  which is exactly what `of: payload` is for. Four such entries were bare strings —
  `agama` with `electron-native-notify`, and JuiceLedger's `exotel` with `spam` — and each
  now says that it names the shared payload rather than either project's own archive.
- **Dates that contradict a checkable source.** `cemu` dated the 2.6 release to February
  2026; GitHub's own release record says 2025-02-06, which makes the swap a fifteen-month-old
  release rather than a four-month-old one.
- **Identifiers that name the wrong thing, or nothing at all.** See the two sections above.
- **The same value under several spellings.** `ecosystem` and `kind` are free text, so they
  drift, and the coverage report then counts one ecosystem as three. `vs code marketplace`,
  `vscode marketplace`, `vscode_marketplace` and `vscode` were four names for one registry;
  `wordpress.org` for `wordpress`; `dockerhub` and `docker` for `docker hub`; `action` and
  `ci_cd_action` for `github_action`. Each was confirmed against the artifact's own
  locations before merging — every VS Code variant points at `marketplace.visualstudio.com`
  — and the report now counts nine VS Code artifacts rather than five, one and one.

Merge only what the record itself proves is the same thing. `extension` and
`extension_package` look like drift and are not: the split runs exactly along browser
extensions versus editor and CMS extensions, so collapsing them would destroy a
distinction the corpus is actually making. The genuine fault nearby was five WordPress
plugins recorded as `extension` while ninety-nine siblings used `plugin`, and one Chrome
extension, `thegreatsuspender`, carrying no ecosystem at all — which means it cannot be
grouped with the other Chrome extension incidents by any query.

None of this is exotic, and all of it is cheap next to the searches that a wrong record
sends someone on.

## What a digest nothing recognises actually means

A digest no sample repository knows is a reason to doubt the digest rather than the
artifact — that is the rule this corpus works by, and 3CX and num2words both sat
unrecovered because it held. But the rule has two exceptions large enough to swamp it,
and both were visible the first time it was run at scale.

Asking VirusTotal about the 258 proprietary digests that MalwareBazaar, Triage and
Spectra Assure all missed returned 147 known and 111 unknown. So more than half of what
looked like a corroboration problem was only a coverage problem: those digests name
files that exist, are widely detected, and simply are not downloadable with the key
available here. Recording them as doubtful would have been wrong.

Of the 111 nothing recognised, 68 appear verbatim in the incident's own archived
references. Those are transcribed correctly and merely unavailable. That leaves 43 in
neither the feeds nor the sources — and the shortlist is still contaminated by two
things worth knowing before treating any of it as an error.

The first is regional coverage. K-System's record carries 23 digests and sixteen are
unknown to every feed, which looks alarming until the source is checked: twenty appear
verbatim in the AhnLab ASEC pages archived beside the record, and the other three are
known to VirusTotal with 44 or more detections. A Korean vendor's IOCs being absent from
Western repositories is the expected case.

The second is artifact kind. Nine of the 43 belong to Checkmarx's KICS image, whose
`kind` is `oci_image`. VirusTotal does not index Docker image or layer digests at all,
so a miss there carries no information — the feed was asked a question it cannot answer,
which is the same mistake as sending a SHA-1 to a feed that only indexes MD5 and
SHA-256. Filter by `kind` before reading the result: `oci_image`, `hardware` and
`android_system_app` are all outside these feeds' catalogues.

What survives both filters is 34 digests across fifteen artifacts, thinly spread. That
is the honest shortlist, and it is a list of questions rather than a list of errors.

A corroboration pass is also a bridging pass, and that is the part with a use beyond
bookkeeping. Of the 147 digests VirusTotal recognised, 69 were MD5 or SHA-1, and for each
of those VirusTotal also reports the file's SHA-256. Twenty-two of those resolutions were
not already on the artifact. That matters because Hopper, MalwareBazaar and Spectra
Assure are SHA-256 addressed: a record citing only an MD5 cannot ask them anything, and
its silence is indistinguishable from a real miss. Recording the resolution, annotated
with where it came from, lets those lanes be asked a question they can answer.

Asked immediately, they mostly still say no — none of the four NetSarang installer
SHA-256s resolved this way is known to MalwareBazaar, Triage or Spectra. That is not a
wasted step. The digest is now on the record, sourced and dated, so the next pass starts
from a usable identifier instead of repeating a lookup that costs quota, and a repository
that ingests the sample later becomes reachable without anyone rediscovering the bridge.

## Reading the reference ledger as an audit

`tools/archive-references.js` keeps a copy of every cited page beside the record that
cites it, and its manifest doubles as a liveness ledger: the status, the date attempted,
whether the request ended up somewhere else, and how much visible text the page actually
held. That ledger answers a question that otherwise needs a thousand network requests —
which records are still supported by their own sources — straight from disk.

Across 2,168 archived references, 81 have actually lost their content. The categories
matter more than the total, because three of them look alike in a naive check and mean
different things.

The largest group, 43, is pages that returned 200 while holding almost no visible text:
a JavaScript shell, a consent interstitial, or a site that has quietly swapped an article
for its own front page. Those pass any check that reads only status codes, which is why
they are worth counting separately. Another 28 redirected offsite — usually a vendor
acquisition dissolving a blog into a corporate landing page — and only 10 are outright
gone with a 4xx or 5xx.

A fourth group, 19 more, must not be counted with them: a 401, 403 or 429 means the
archiver was refused, which says nothing at all about whether the page is still there.
VestaCP is the example to keep in mind. It looks like the worst record in the corpus
until the categories are separated, and then it is not affected at all: its six failures
are its own forum, cvedetails and hackread answering 403 to any automated client, while
the sources the record actually rests on — both Vesta commits, the ESET writeup and the
NVD entry — are healthy and hold thousands of characters each. Reporting those as rotted
references would have sent someone hunting for replacements that were never needed.

The check is worth running against a specific record whenever its prose reads vaguer
than the incident should allow, because the two facts are usually connected. SimDisk is
the pattern: its story says only that researchers "linked malware delivery to an update
installer", and its ledger shows the Avast post returning 282 characters of text and the
Symantec post redirecting to a Broadcom landing page. The detail was not missing from
the research, it was missing from the sources by the time anyone looked — and the names
the record needed, Trojan.Castov and TROJ_DIDKR.A, were still recoverable from the
secondary reporting that outlived the primary.

## The member that cannot be rebuilt is usually package.json

Reconstruction stalls on a specific file more often than on the payload. Of the weak
evidence artifacts that came within one or two members of completing, 47 were missing
only `package.json`, against 15 missing `lib/commonjs/index.js` and 9 missing `bundle.js`.

It is tempting to derive it. The predecessor publishes a `package.json` that differs, on
the face of it, only in a version string, and jsDelivr records the SHA-256 of the real
one, so a candidate can be checked rather than assumed. That check is worth running
precisely because it is free to be wrong: swapping the version in the predecessor's file
reproduced the recorded digest for **none** of the eight tried.

The reason is the attack itself. In these compromises `package.json` is not incidental —
it carries the `postinstall` hook that runs the payload, so it is one of the files the
attacker edited. Deriving it from the clean predecessor cannot work, and a reconstruction
missing it is missing evidence rather than boilerplate. Where the bytes do not survive in
Hopper or Software Heritage, the archive stays incomplete and honest.

Software Heritage is worth asking anyway, but its coverage is uneven in a way that maps
onto how a file travelled. For the missing members of partial captures it answered 108 of
113. For these weak evidence artifacts it answered 3 of 59. A payload file that circulated
and was analysed gets archived; a package's own manifest, altered once and unpublished
days later, does not.

## Completing a partial reconstruction

A partial reconstruction is an archive that is missing members, kept as `payload_only`
with a `.partial.json` listing what is absent. The corpus had 991 of them, and the
absent file was overwhelmingly the same one: `router_init.js`, the Shai-Hulud loader,
missing from 391.

They are completable because two independent things survive a version being unpublished.
jsDelivr keeps the file listing with a SHA-256 for every member, which is both the recipe
and the proof; and the payload that was reported is exactly the file a research corpus is
likely to hold, so Hopper has it. `tools/reconstruct-npm-release.js` puts those together:
keep every member already inside the partial whose digest matches the manifest, fetch the
rest by digest, re-measure, and fail closed if any member cannot be verified. It builds on
a registry predecessor by default and on a local partial with `--base-tarball`, which is
the mode that matters here — for these packages *every* version was removed, so no
predecessor exists to fetch.

Of 720 partials surveyed, 402 were completable, 200 had no jsDelivr manifest, and 118 had
missing members Hopper does not hold. 255 were completed and recorded; the difference is
explained below.

Two implementation details are not optional. The tar must be written by hand: BSD tar has
neither `--mtime` nor GNU's `-T`, so shelling out cannot produce reproducible bytes, and
without pinned mtime, uid, gid, uname and gname the same inputs give different archives.
And ustar's 100-byte name field is not enough for real npm paths — `dist/cjs/rules/<long>/<long>.cjs`
overflows it — so the 155-byte `prefix` field has to be used, splitting the path at a
slash. The first full run died on exactly that.

The mistake worth recording is the output path. Deriving it by rewriting `-partial.tgz`
to `-RECONSTRUCTED.tgz` collides with reality in two ways: some partials live in a `base/`
subdirectory beside a *complete* reconstruction that already exists at the parent path,
and some versions have both a `-partial.tgz` and a `-RECONSTRUCTED-PARTIAL.tgz` spelling
that map to one output. Writing blind overwrote 13 committed reconstructions and put 132
files in `base/` directories where they did not belong. The corpus verifier caught it
immediately — a recorded digest no longer matched its file — and every overwritten file
was restorable from git because it was committed. Check whether the output already exists
before writing it, and treat a digest mismatch on a file you did not mean to touch as the
signal it is.

The 200 with no manifest are a hard stop rather than a lane not yet tried. jsDelivr,
unpkg and the npm packument were all asked: the CDNs 404 the purged versions and the
packument keeps `time` entries without file lists. With no member list there is nothing
to verify a rebuild against, and an unverifiable rebuild is not worth making.

## Software Heritage indexes what the malware feeds do not

Software Heritage archives source code — package registries, git forges, source
releases — and it indexes content by SHA-256, so a digest can be asked for directly at
`/api/1/content/sha256:<digest>/` and fetched from `.../raw/`. Nothing else in this
toolchain covers that ground. Hopper, MalwareBazaar, Triage and Malshare are malware
repositories; a source tarball that no one submitted to a sandbox is invisible to all
four, and four passes over the same digest will report it unavailable four times.

vsftpd 2.3.4 is the case that proves it. This record held a diff, a reconstruction, and
an interpretation stating that the exact poisoned tarball "remains unavailable" — after
that digest had been put to every hash lane the corpus uses. Software Heritage had it.
The recovered file measures to the digest the record cites, its gzip container records a
modification time of 2011-06-30 14:17:36, and `str.c` line 572 carries the trigger: a
test for `0x3a` followed by `0x29`, the `:)` sequence, calling `vsf_sysutil_extra()`.

The lesson is about matching the lane to the artifact kind rather than about one file.
Ask Software Heritage for anything whose `kind` is a source archive, a package release,
or a git tree, and ask it before concluding that a hash lane's silence means the artifact
is gone. Its anonymous rate limit is 120 requests an hour, which is slow but not a
barrier — a full sweep of this corpus's unheld source digests is a few hours unattended.

The Internet Archive's item search, by contrast, is not a lane for this corpus. Searching
its software and data collections for all 89 unresolved proprietary artifacts by name
returned 38 candidates and not one match: generic GitHub repository mirrors and unrelated
shareware compilations that share a word with the query. The Wayback Machine remains
valuable for mutable URLs; the item collections are not where vendor installers live.

## WordPress needs the vector decided before anything is fetched

The plugin and theme directory will serve any version it still lists, so a WordPress
baseline is trivial to download and easy to record wrongly. What decides whether the
download means anything is where the compromise actually travelled.

AccessPress is the case that settles it. The same themes were clean when installed from
WordPress.org and backdoored when installed from the vendor's own site, so a copy from
the directory at the affected version number is a *same-version comparator*, not a
predecessor. Filing 89 of those as before samples would have said something false about
what the directory served. The record already holds them correctly, as clean comparators
alongside recovered vendor archives, and the incident is excluded from the baseline lane
entirely.

The other WordPress incidents here ran through the directory itself — a stolen commit,
a compromised build pipeline, a publisher account closed after the fact — and for those a
directory download is the same channel the compromise used. Advanced Responsive Video
Embedder is the clean example: 10.8.6 and 10.8.9 bracket the incident, and 10.8.7 and
10.8.8 are both absent from the version list today, which is the directory confirming what
happened.

What blocks the rest is not access but identification. The essentialplugin campaign covers
31 plugins and the record establishes an affected version for one of them; BdThemes has
eight artifacts and no recorded versions at all, because the compromise was in the vendor's
update mechanism rather than in a published file. Without a version to anchor to there is
no predecessor to choose, and the archived references do not supply one — a search across
them yields a single slug-to-version pair among several hundred numeric strings that are
mostly stylesheet noise. That is a research gap, and inventing the anchor to close it
would be worse than leaving it open.

## Baselines are cheap, and most of them were missing

The predecessor and successor of a compromised release are the two files that make a
during artifact legible: with all three, the diff shows exactly what the attacker changed.
They are also the easiest things in this document to acquire, because the registry usually
still publishes them even when the malicious version is gone — and it publishes a digest
for them, so the download verifies itself.

Running that against npm produced 601 baselines in one pass, every one reproducing the
`dist.integrity` sha512 the registry records. Across the corpus the before phase went from
219 samples to 848 and the after phase from 106 to 416. PyPI, Packagist, RubyGems and
crates.io answer the same way through their own indexes, though Packagist publishes no
per-file digest, so those are recorded `probable_exact` rather than `exact`.

Two cautions. The first pass keyed the target list off sample coordinates and found 165
artifacts; keying it off `package` and `versions` in `meta.yaml` found 544, because most
artifacts declare their versions there and carry only an evidence fragment as a sample.
Build the list from the record, not from what is already held.

The second is that a missing successor is a finding rather than a failure. Of 1,009
attempts, 396 had no version above the compromised one: the package was abandoned, not
fixed. That is worth knowing about an incident, and it is invisible if the absence is
filed as an acquisition error.

WordPress is deliberately excluded from this lane. For AccessPress the .org channel served
the same version number cleanly while the vendor's own site served the backdoored zip, so a
download from .org is a same-version comparator, not a predecessor. Recording it as a
before sample would misdescribe what it is.

## Which lanes are exhausted, and what is left

This is the state after working the retrieval routes the corpus has access to. It is
recorded so the next pass starts from what has already been ruled out rather than
repeating it. It is not a claim that nothing remains: Software Heritage was added to the
lanes after this section was first written and immediately produced vsftpd 2.3.4, and its
sweep of the remaining source-shaped digests was still running when these numbers were
taken.

Every open-source incident holds during bytes: 189 of 189, 752 archives are complete
reconstructions rather than partial captures, and the corpus holds 848 before and 416
after baselines against 2,645 during samples. On the proprietary side 81 artifacts hold a
during sample and 85 do not, and those divide three ways.

**31 artifacts are held up by download rights alone.** VirusTotal identifies the file —
name, size, detection count — and refuses `/download` to a free key with an explicit 403.
Asking the repositories that do serve files does not help: all 114 digests on these
artifacts were put to MalwareBazaar and Triage using only the algorithms each indexes,
and exactly one came back. VirusTotal's catalogue is simply wider than theirs. A key with
download rights would likely convert most of this bucket in one run; nothing else will.

**16 artifacts carry a digest no provider will serve.** Hopper, MalwareBazaar, Triage,
Malshare and Spectra Assure have all been asked. MalwareBazaar was also asked by
signature and by tag — GoldenSpy, XRed, Floxif, ShadowPad, SUNBURST, Havex, Dofoil,
1,268 tagged samples between them — and none matched a wanted digest. Their vendor
download URLs were requested with a browser user agent and are dead or unreachable.

**42 artifacts have no digest at all**, and for most of them that is a limit of the
published research rather than a search that was not run. The kinds tell the story: 13
binary archives, 6 firmware images, 5 browser extensions, 5 source archives, 3 floppy
disks, 3 GitHub Actions, and singletons down to one physical CD.

Lanes tried and closed, with what closed them:

- **Sample feeds by hash**: Hopper, MalwareBazaar, Triage, Malshare, Spectra Assure.
- **Software Heritage by content hash**, which covers source archives none of the malware
  feeds index and which produced vsftpd 2.3.4, the MiMi Linux rshell, colors.js's
  `american.js`, Tiledesk's injected workflow, and three more.
- **jsDelivr and unpkg file listings**, both as the recipe for completing a partial
  reconstruction and as the proof that a rebuild is right.
- **MalwareBazaar by signature and tag**, which finds campaign-adjacent samples but never
  the specific artifact.
- **VirusTotal**, for identification only; its free key cannot download.
- **VirusSign**, which sells bulk daily packs and has no per-hash retrieval at all.
- **The Internet Archive**, both as window diffs against mutable URLs and as CDX coverage
  checks on distribution paths. This is the lane that produced BrowseAloud and StatCounter,
  and the one that fails whenever coverage skips the window — Twilio, Alpaca, British
  Airways, Codecov, Ammyy all have that shape.
- **URLhaus**, across all 148 proprietary distribution hosts: one substantive hit, a
  second SolarWinds path with no payload attached.
- **Container registries**: Docker Hub by manifest and by blob, and mirror.gcr.io as a
  pull-through cache that sometimes outlives upstream deletion. All nine KICS image
  digests are gone from both, with `checkmarx/kics:latest` answering 200 from the mirror
  to prove the endpoint works.
- **GitHub**: commits by SHA, tags, releases and forks. Malicious commits appear to be
  purged rather than merely unreferenced, and the fork created 39 minutes after the
  Checkmarx April window heads at a clean commit.
- **npm and npmmirror**, including packuments whose `time` field still names removed
  versions after the tarballs are gone.
- **crx4chrome and the Archive for CRX files**: the version histories survive and are
  where several extension digests in this corpus come from, but the packages themselves
  are not served and the Archive holds no capture of any URL containing these extension
  ids.
- **MEGA public folders**, which needed a client written for them, and which turned out to
  hold Procolored's remediated builds rather than the compromised ones.
- **Researcher mirrors**: pastebin, gists, and code published as images. Reading a
  screenshot is how the British Airways skimmer and its real URL were recovered.
- **archive.org software collections**, for the physical-media and pre-2000 artifacts.

What would move the number, in order: a VirusTotal key with download rights (31
artifacts), a researcher's private copy of a pulled browser extension (5), and vendor
cooperation for installers whose download hosts are gone (much of the 16). Nothing else
in reach was left untried.

## Hopper answers 200 when it cannot serve the file

A content-addressed store makes an obvious probe: ask for the digest and read the
status. For Hopper that probe is wrong. It answers `200` for digests it holds a record
of but cannot actually serve, with a short body in place of the file — one of them reads
`{"error":"corrupt archive"}` — so a sweep that trusts the status code reports files
that are not there.

Three Red Hat cloud-services digests came back `200` this way and looked like
recoveries until the bytes were measured: 31, 176 and 37 bytes, none matching the digest
requested. The rule is the same one the rest of this document applies to every other
provider — the answer is the measured digest of what comes back, never the transport
status. Fetch, hash, compare, and only then call it a hit.

The same sweep found three genuine ones, which is why it was worth running: the
`execution.js` member for `@cap-js/postgres` and `@cap-js/db-service`, and the sabotaged
`lib/index.js` from colors.js. All three had been recorded unresolved on the strength of
a Hopper 404 against `10.9.8.5`, the address the store used before it moved. A negative
obtained from a decommissioned host is not a negative, and these three are what that
costs.

## Mining the references for digests does not work in reverse

Checking whether a digest the record already cites appears in the record's own archived
references is worth doing: it separates a digest transcribed correctly from a source
nobody indexes from a digest that may simply be wrong, which is what settled K-System.

Running that in the other direction — scanning the references for digests the record does
not carry, in the hope of finding an IOC nobody transcribed — does not work. Tried across
the 45 artifacts holding no digest at all, it produces mostly furniture. Filtering to
digests that appear in at most two incidents still leaves candidates that are not file
hashes: the Juniper record's most distinctive-looking value,
`3c3c3c20257328756e3d2725732729203d202575`, is the backdoor password `<<< %s(un='%s') = %u`
written as hex, and a run of near-identical MD5-shaped strings sharing the prefix
`192d8c76b6ae80` are generated page identifiers rather than hashes. Bean Battles yields
nineteen SHA-1-shaped strings that are git commit ids.

Five of the most plausible survivors were checked against VirusTotal and every one came
back unknown. A digest worth having is almost always presented as one — in an IOC table,
beside a filename — and the ones that are not presented that way are usually not digests.
Spend the quota confirming what the record already claims instead.

## The digest may already be on disk

A digest no feed recognises has two very different explanations, and they call for
opposite responses: the digest is wrong, or it names a file that was never published
on its own because it travelled inside something else. An installer, a release
archive, or a disk image is one artifact to a registry and several files to a report,
and reports routinely list an inner file's digest beside the container's without
saying which is which. When that is what happened, the bytes are already in the
corpus and only the record is missing — so an artifact can sit marked unavailable
while the thing it names is sitting unpacked one directory away.

So before an unresolved digest is treated as an unavailable artifact, ask whether
the corpus is already holding it. `tools/resolve-member-digests.js` unpacks each held
sample, measures every member in all three algorithms, and reports the citations that
match. Extraction is not installation, nothing is executed, and the unpacked copies
are deleted as soon as they are measured.

Two distinctions keep the answers honest. A sample stored compressed satisfies its
digest through the bytes inside the wrapper, so decompressing a `.xz` is not unpacking
a container and the single file it yields is the sample itself, not a member of it —
without that exception every compressed sample in the corpus reports as a false match.
And a member digest is recorded with `of: payload` and a note naming the member path
and its size, because `of: archive` on an inner file is the same claim as recording
the container's digest twice.

This found four such digests in the open-source records and one in the proprietary
ones. CCleaner is the clearest: Talos published three SHA-256s in one undifferentiated
IOC list, two of which were attributed here and one of which was not, and the missing
one turned out to be the trojanized `CCleaner.exe` carried inside the 5.33.6162
installer that this corpus had held all along. The Transmission case is the most
instructive, because measuring the members is also what exposes the disguise: the
KeRanger payload shipped as `Contents/Resources/License.rtf` and is 3,035,136 bytes,
which is not a licence text.

## Hash subjects and roles

A digest on its own does not say what it covers. The same SHA-256 appears on two
different packages in this corpus, which is only coherent if it names a shared
payload rather than either archive — and nothing in the data said so, which left
the entry indistinguishable from an error. A separate case recorded an MD5 for a
trojaned tarball that was never recovered, so no such digest can exist.

Hash entries therefore take three optional fields:

```yaml
hashes:
  - sha256: 5f2b...
    of: archive          # archive | file | payload
    path: dist/index.js  # required when of: file, meaningless otherwise
    role: malicious      # malicious | clean
    note: free text
```

- **of** — `archive` is the artifact as distributed, `file` is something inside
  it, `payload` is a stage the artifact fetched or dropped and so has no path
  within it.
- **role** — `malicious` identifies the attack; `clean` is a known-good build
  kept for comparison. A baseline recorded without this reads as an indicator,
  which is how several ended up buried in prose instead.

Both older forms (`- sha256:5f2b...` and `- sha256: 5f2b...`) still parse and
mean "a digest, subject unstated". Nothing needs migrating; the fields exist so
that new entries can be checked against a stored sample, and so an unverifiable
digest can be marked rather than quietly asserted.
