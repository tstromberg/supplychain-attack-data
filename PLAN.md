# Splitting the corpus: events in git, artifacts in a data store

## Why

The repository is 15 GB: a 10.2 GB working tree and 5.4 GB of git history.

| Component | Size | Files | Share of tree |
|---|---:|---:|---:|
| sample payload bytes | 9.39 GB | 14,703 | 92.2% |
| refs (archived source pages) | 0.68 GB | 2,659 | 6.7% |
| manifest.yaml | 23 MB | 293 | 0.2% |
| provenance sidecars | 19 MB | 14,189 | 0.1% |
| meta.yaml | 3 MB | 316 | 0.03% |

Payload bytes are 92% of the tree and none of the reviewable content. Eight samples
already exceed what git will carry and are excluded by `.gitignore`, which means they
exist on one machine and nowhere else — the failure this plan removes.

## Principles

1. **Git is authoritative for all text.** Records, manifests, provenance, tools, docs.
2. **The artifact tree is generated.** Everything in it except the bytes is derived from
   git and can be rebuilt. Nothing in it is edited by hand.
3. **Data dominates.** Where a consumer would have to infer something, put it in the
   manifest instead. Every consumer inferring the same fact is a schema defect.
4. **A path is for humans; a digest is for proof.** Both are recorded; neither is
   sufficient alone.
5. **Uniform shape beats special cases.** One path layout, no conditional segments.

## The two stores

### 1. Event repository (git) — ~750 MB

```
oss/attacks/<id>/meta.yaml
oss/attacks/<id>/refs/…                        archived source pages
oss/attacks/<id>/samples/manifest.yaml         the index: digests, versions, verification
oss/attacks/<id>/samples/provenance/<sha256>.json
tools/  cmd/  docs/  *.csv
```

Provenance keys on digest rather than living in the phase tree, so re-phasing a sample or
renaming an artifact never moves it. That churn is real: one session moved 754 samples
between phases and renamed several artifact ids, dragging a sidecar along each time, and a
rename that fails halfway separates bytes from their history permanently.

Two details of the store were settled by the data rather than by the design. **It holds a
list, not a record.** The same bytes are frequently acquired more than once — one AUR
`.desktop` file arrives byte-identical from nine different commits, and 549 of the 574
duplicate-digest groups in the corpus carry genuinely different acquisition records — so a
file holding one of them would discard the rest. And it stays **JSON, not YAML**: these are
collector outputs full of ISO timestamps, and a YAML round-trip coerces those to dates. The
corpus has been bitten by that before, which is why `build-artifacts.js` carries an
`isoDate` helper at all.

`refs/` stays in git. Archived source pages are evidence about the *event*, they are
diffable text, and they are 7% of the tree.

### 2. Artifact tree — `~/data/supplychain-attack-data`, synced to R2, ~9.4 GB

```
<record-id>/
  README.md                                    generated
  pairs.yaml                                   generated
  <subject>/<phase>/<release>/<filename>
  <subject>/<phase>/<release>/parts/<filename>       components and fragments
  <subject>/<phase>/<release>/provenance.yaml        generated
```

Real files, original names, no compression containers.

## Path layout

```
<record-id>/<subject>/<phase>/<release>/<filename>
```

Five segments. No optional levels.

- **`record-id`** is flat and unique corpus-wide. `oss/` versus `proprietary/` is a
  taxonomy detail, not something a researcher navigates by.
- **`subject`** is the thing that was compromised — an npm package, an AUR package, an
  installer. This must be an explicit field, not inferred; see "Schema changes".
- **`phase`** is `before`, `during` or `after`.
- **`release`** is the version as the distributor wrote it, the source commit where that is
  the release identity, or the literal `unversioned`. `ls <subject>/before | sort -V` is
  the release chain.
- **`filename`** is the name the artifact was distributed under, unchanged.

### Why the version is a directory and not just part of the filename

An earlier draft of this plan put the version in the filename alone, on the grounds that
88% of (subject, phase) groups hold exactly one version, so the segment would be an empty
level for the large majority. That argument was wrong, for two reasons the data made
plain once the tree existed.

**Filenames do not reliably carry the version.** Of 4,707 samples with a version, 628 do
not show it in the name. The AccessPress plugins are the clearest case: they were
recovered from the Wayback Machine, so the stored name is the capture timestamp —
`20211011003032-accesspress-custom-css.zip`. That records *where we found it*, which is
the `recovered_from` question, not *what it is*. Rewriting the name to inject the version
would forge a filename that never existed, so the version has to go somewhere else, and
the path is the only place a researcher sees without opening a file.

**Parsing a version back out of a filename is unreliable.** Distributors write versions as
they please: `openssh-3.9p1-11.el4_7.src.rpm`, `2.0.13-848.v76e89de8a_053`,
`multilogin-2.4-1.2.9.tar.gz`. A first pass at this in `backfill-versions.js` read `525`
out of `bash-uploader-line-525.fragment` and would have filed a Codecov fragment under a
release that never shipped. A consumer should not have to repeat that guess — and today
`isomer` does, in `version_affinity()`.

The cost is real and was paid deliberately: ~6,000 release directories, of which the large
majority hold one file. Directory count is cheap; a version a researcher cannot see, or
has to regex out of a name, is not.

Filename collisions are *not* among the reasons. All 33 are same-subject, same-phase,
same-version, same-name, different-bytes — genuine record defects that a version directory
does nothing about. The generator disambiguates them with a short digest suffix **and
reports every one**, so the defect stays visible instead of being papered over.

Examples:

```
laravel-lang/laravel-lang-lang/before/15.29.4/laravel-lang-lang-15.29.4.zip
accesspress-themes/accesspress-custom-css/during/2.0.1/20211011003032-accesspress-custom-css.zip
arch-aur-atomic-arch/privacy-redirect-git/during/a5770512c0a0de6ecea0649a0e8cf5f54e656433/PKGBUILD
coa/coa/during/unversioned/sdd.dll
```

### Samples are stored uncompressed, and `artifacts/` is gone

Two representations existed only because payload bytes used to live in git, and both were
retired once they did not.

**The xz storage containers.** A sample over 75 MB was held compressed with a `storage`
block naming the container. That bought 9% on files that are already archives, and for
eight samples it bought nothing at all -- still over GitHub's 100 MiB limit, so they were
excluded from the repository entirely. `tools/decompress-samples.js` removed all 18
containers after checking each decompressed to the digest the manifest records;
`make samples-verify` now rejects a `storage` block, and `tools/sample-storage.js` is
deleted.

**The legacy `artifacts/` staging trees.** Four records still carried one beside
`samples/`. It predates the manifest -- several manifest entries cite it as their source
url -- and nothing saw it: not the verifier, not the tree builder, and not the ignore rules
for the split, because it is not under `samples/`. It would have been the last payload
bytes left in git. Of 71 files, 65 were already held (9 as samples outright, 56 as members
of archives that are themselves samples) and one was a `.DS_Store`. The other five were
held nowhere and are now registered: four rand-user-agent payload stages and the malicious
tj-actions commit message. The `meta.yaml` evidence blocks that pointed into the staging
trees were repointed at the samples, and the 14-module comparison subset that the
ultralytics directories encoded is recorded as an artifact note, since that curation was
the only thing the directories said that the archives do not.

### The repeated `<record>/<subject>` level stays

In 133 of 293 records the only subject is named the same as the record, so the path reads
`actions-cool/actions-cool/before/…`. It is redundant and it looks careless. It stays
anyway, and not for aesthetic reasons:

- **Collapsing it makes the tree two shapes.** A record would hold either phase
  directories or subject directories, and nothing in the path says which. Every glob and
  every `find -mindepth N` needs two patterns, and the one a reader writes first is wrong
  half the time.
- **Collapsing it makes paths unstable.** A record with one subject today can gain a
  second tomorrow — that is ordinary corpus growth, and it happened repeatedly this year.
  Under a collapsed layout, adding that sample *reshapes existing paths*: every file under
  the record moves down a level. Those paths are R2 object keys and external citations.
  A redundant directory costs a reader one `ls`; a path that changes when unrelated data
  arrives costs everyone who linked to it.

The 86 single-subject records whose subject differs from the record id — and the 74
records with several subjects — need the level regardless, so collapsing would buy
uniformity nowhere and cost it in two places.

### Complete artifacts and fragments are separated

A release directory holds **only complete distributed artifacts**. Components and
fragments — anything whose `verification.status` is `payload_only`,
`verification_material`, `exact_reported_fragment`, `substitute`, `diff_only` or
`disputed` — go in a `parts/` subdirectory:

```
nextmove-mcp/during/0.1.7/nextmove-mcp-0.1.7.tgz     the distributed artifact
nextmove-mcp/during/0.1.7/parts/bundle.js            a payload component
```

This is the change that makes the tree usable **without reading any YAML**. Today 399
directories mix a complete capture with a fragment, so a consumer comparing
`before/*` against `during/*` would diff a full tarball against a loose payload
file. That is the reason `isomer` parses manifests at all: its `pick()` prefers "an
independently verified complete capture over a partial one", recovering a distinction the
directory layout does not currently express.

Completeness is about **whether the bytes are the whole artifact**, not about how they were
obtained. A reassembled tree that reproduces the full distributed archive is complete and
sits at the release level; a fragment is a fragment whether it was captured or rebuilt.
Concretely: of the 692 samples carrying a `source.reconstruction` block, the 520 that are
`tree_equivalent` are complete artifacts, and the 172 that are `payload_only` go to
`parts/`.

With the split, three rules hold without a parser:

- `<subject>/<phase>/<release>/*` is always a valid comparison input
- a phase directory containing only `parts/` means **no complete artifact was ever
  recovered** for that phase — the honest signal, currently discoverable only from
  `verification.status`
- `ls <subject>` shows which phases exist; `ls <subject>/<phase> | sort -V` gives the
  release chain directly, with no filename parsing

`provenance.yaml` remains available for consumers that want fidelity, digests and
acquisition history, but nothing needs it for the common case.

### Fidelity is visible without opening a file

A researcher must be able to see how good a sample is — captured, reassembled, or partial —
while browsing. Three mechanisms, cheapest first:

1. **The filename says so, and the generator decides it.** The convention already exists —
   `…-RECONSTRUCTED.<ext>`, with `tools/bind-registry-digests.js` renaming away from the
   suffix when a registry digest later proves the bytes exact. Keep it, but derive the name
   from metadata at generation time rather than trusting the name stored today:

       name = original filename, plus `-RECONSTRUCTED` when the sample is a reassembly
              (`source.reconstruction` present, or `source.kind: reconstructed_distribution`)

   Deriving it is what keeps the two signals from disagreeing. They disagree now: of 1,315
   samples where either signal fires, 953 agree, 53 are named `-RECONSTRUCTED-PARTIAL` while
   their metadata calls them `existing_unlisted_payload` (honest — they are partial, and they
   land in `parts/` regardless), and **309 are reassemblies whose filenames look like
   captures**. Of those, the 77 that are `tree_equivalent` are the dangerous ones: complete
   reassemblies sitting at the version level under names like `@asyncapi-generator-3.3.1.tgz`,
   which is not even npm's spelling for that tarball. Generating the name removes the whole
   class without a mass rename.

2. **`fidelity.tsv` at the tree root** — `path → status → basis → reconstructed`. One
   `grep tree_equivalent fidelity.tsv` lists every reassembly in the corpus; one `awk`
   filters to exact captures. Regenerable, not authoritative.

3. **The record `README.md` carries a table** of each file with its phase, version,
   fidelity and digest, so landing in a record directory shows the quality of its evidence
   without opening anything else.

`provenance.yaml` leads with `status` and `basis` for consumers that want the full
reconstruction chain: method, inputs and their digests.

**Metadata is the source of truth for fidelity, not the stored filename.** The rule above
makes the generated tree self-consistent, so the 362 disagreements in the current tree need
no mass rename — but `source.kind` should still be normalized so `reconstructed_distribution`
and a `source.reconstruction` block are not two ways of saying the same thing.

### Where a sample came from, at a glance

"Where did this come from" is two questions, and the corpus currently answers them
unevenly: **99% of samples record the URL we acquired from (`source.url`) and only 15%
record where the attack distributed it (`source.original_url`)**. Worse, whether the
acquisition URL *is* the distribution point depends on `source.kind` — it is for
`distribution` and `official_registry`, and emphatically is not for `malware_sandbox`,
`research_corpus` or `malware_repository`. A researcher should not have to know that
vocabulary to read a provenance record.

`provenance.yaml` therefore names the two separately, and the generator fills the
distribution side from the best available evidence: `source.original_url`, else
`source.url` when `source.kind` means the acquisition *was* from the distribution point,
else the artifact's declared distribution location in `meta.yaml` — which covers **92% of
artifacts**. Where none exists it says `unknown` rather than guessing.

```yaml
subject: elmedia-player
phase: during
files:
  - file: Elmedia-Player-trojanized.dmg
    sha256: c9140c869123e0c7a4d064a9e82bb1549c3e382cdcf2c119bcbe78911915208b
    size: 40571874
    fidelity: exact
    basis: [reported_sha1, measured_sha256]
    distributed_from: https://www.eltima.com/products/elmedia-player/   # the attack's channel
    recovered_from: https://tria.ge/api/v0/samples/240306-n9zacaad2t/sample
    recovered_via: malware_sandbox
    recovered_at: 2026-09-11T12:00:00Z
    note: >-
      Recovered as a member of the submission Proton.C.zip, which bundles the OSX/Proton
      set this campaign delivered.
```

The two lines read very differently on purpose. `distributed_from` is where a victim got
it; `recovered_from` is where we found a surviving copy years later. When they are the
same URL the generator says so explicitly rather than repeating it.

A reassembly carries its inputs in the same record — method, each input's URL and digest —
so the chain from published bytes to the file on disk is readable without leaving the
directory.

The record `README.md` repeats the distribution URL per subject, so the common question is
answered before opening anything.

### Finding a subject without knowing its record

`by-subject.tsv` at the tree root maps `subject → record-id`, so a consumer that knows
only a package name can locate it in one lookup. It is a text file rather than a directory
of symlinks because object storage has no symlinks and `rclone` would either skip them or
silently copy their targets.

## Schema changes in git

These are the changes that let the tree be generated without inference.

1. **An explicit subject.** Today `artifact_id` identifies the package in
   `laravel-lang` (504 versions of one package, `package` unset) while a single
   `artifact_id` stands for ~1,800 packages in `arch-aur-atomic-arch`, where `package`
   does the discriminating and `version` is set on 3 of 7,800 entries. The same field
   means different things in different records. Normalize so one field always names the
   subject.

2. **Fix the 60 colliding groups** — filenames that contradict their `version` field,
   comma-joined version scalars, and duplicate entries at one version.

3. **Record store presence**: `store: {present: true, synced_at: …}` per sample, so
   holdings can be reported without reaching for R2, and a sample whose bytes are absent
   is visibly lost rather than silently assumed.

4. **`verification.basis` is an enumerated vocabulary** of 22 terms, validated by
   `tools/verify-oss-samples.js` against the list `tools/normalize-basis.js` exports.
   *(Done.)* It had drifted to 1,413 distinct values, 937 used exactly once, in strings
   like `retained_jsdelivr_manifest_accounts_for_all_1280_members` — sentences with the
   spaces removed, which nothing could group by. The particulars they carried are real
   evidence, so the split is lossless: the terms go in `basis`, the original strings stay
   verbatim in the new `verification.evidence`, which is deliberately free text. 98.4% of
   uses classify; the residue keeps its string in `evidence` and contributes no term, so
   an unrecognized value reads as unexplained rather than being forced into the nearest
   bucket. `normalize-basis.js` is idempotent — on a re-run `evidence` is the input, so a
   second pass cannot overwrite the originals with the terms derived from them.

5. **Reject duplicate YAML keys in `cmd/yaml2csv`.** The Go loader accepts them and takes
   the last; `js-yaml` refuses the file outright. `make run` has twice passed while the
   coverage tooling was broken.

## Generated files in the artifact tree

| File | Purpose |
|---|---|
| `BUILD.yaml` (root) | the git commit the tree was built from, build time, tool version |
| `<record>/README.md` | title, dates, synopsis, what each phase holds, digests |
| `<record>/pairs.yaml` | the comparisons and their expected outcomes |
| `<subject>/<phase>/<release>/provenance.yaml` | per-release provenance, so bytes never travel naked |
| `by-digest.tsv` (root) | `sha256 → path`; a regenerable cache, not authoritative |
| `by-subject.tsv` (root) | `subject → record-id`; a regenerable cache, not authoritative |
| `fidelity.tsv` (root) | `path → status → basis → reconstructed`; a regenerable cache |

`provenance.yaml` is one file per directory rather than one per artifact: it keeps a
listing to the artifacts plus one obviously named metadata file, it cannot collide with a
sample's own name (13 samples are themselves `.json`), and it reads better where a
directory holds several related members. It is YAML because the rest of the corpus is.

`by-digest.tsv` recovers what abandoning content-addressed storage gives up — reverse
lookup, and visibility of the 572 digests that appear in more than one record — as a text
file rather than duplicated bytes.

### pairs.yaml

The differential expectations belong in the corpus, not in each consumer:

```yaml
- kind: attack        # before -> during
  expect: detect
  old: {subject: …, phase: before, version: 3.0.2, sha256: …}
  new: {subject: …, phase: during, version: 3.0.3, sha256: …}
- kind: remediation   # during -> after      expect: no-detect
- kind: net           # before -> after      expect: no-detect
- kind: baseline      # before -> before     expect: no-detect
```

`isomer`'s `validate-samples.py` is roughly 900 lines, most of it reconstructing facts the
corpus already knows: `pick()`, `version_affinity()`, `file_form()`,
`sample_logical_name()`. Publishing the pairs turns that into a loop and makes the
corpus's intent reviewable in a diff. Generate them, with a small curated override file in
git naming only the cases where the heuristic chooses the wrong comparator.

## Verification

`make verify-store` compares the contract (git manifests) against the tree:

| Failure | Meaning |
|---|---|
| `missing` | a manifest names it, the tree lacks it — **lost** |
| `extra` | bytes no manifest claims — orphan |
| `mismatch` | digest differs — corruption or the wrong file |
| `stale` | `BUILD.yaml` commit is not an ancestor of `HEAD` — regenerate |

The build is incremental: a file is written only when its digest differs from what is
already there, so a rebuild after a metadata-only change costs no bulk I/O.

## Sync

`rclone sync` the artifact tree to R2, **with object versioning enabled**. Re-phasing moves
an object, so keys are mutable; versioning keeps old references resolvable and makes a
destructive sync recoverable. The README must state that **the digest, not the path, is
the citable identity**.

Partial fetch works naturally: `rclone copy r2:corpus/<record-id>/` pulls one record, and
the git manifest verifies it. Prefix copy is straightforward precisely because the tree is
path-organised — a real advantage of this layout over content-addressed storage.

## Migration

Steps 1–4 touch nothing that exists and are fully reversible.

1. `tools/normalize-subjects.js` — make the subject explicit, backfill versions. Report
   only, then apply.
2. `tools/build-artifacts.js` — read manifests, verify every digest, write the tree with
   `provenance.yaml`, `README.md`, `pairs.yaml`, `BUILD.yaml`, `by-digest.tsv`. Report any
   sample whose bytes are missing.
3. `make verify-store` — prove the tree matches the manifests and that no sample was lost.
4. Compare against the current tree file-by-file to prove nothing is dropped.
5. Move provenance sidecars to `samples/provenance/<sha256>.json`. *(Done:
   `tools/migrate-provenance.js` read 14,043 sidecars into 12,131 digest-keyed documents,
   collapsing 1,912 identical acquisitions and leaving 0 samples without provenance. 136
   records belonging to auxiliary files and 2 genuine orphans were reported and left in
   place. Eleven tools now write through `tools/provenance-store.js`.)*
6. `git rm -r --cached` the payload paths; add ignores.
7. `rclone sync` to R2 with versioning on.
8. Repoint `isomer` at the artifact tree and `pairs.yaml`; delete its inference code.

## Open decisions

**Git history.** `.git` is 5.4 GB and stays that way unless the payload blobs are removed
with `git filter-repo`. That reduces a clone to roughly 1 GB but rewrites every commit
hash. Worth it if the repository is meant to be widely cloned; skip it otherwise.

**Historical reproduction.** R2 holds one live tree; git holds history. Checking out an old
commit does not give the tree as it was. Digests always allow *verifying* whatever is
fetched, but reconstructing a past layout needs R2 versioning plus `by-digest.tsv`. If
exact historical reproduction matters more than browsability, the alternative is
content-addressed storage with the browsable tree generated locally — that trade should be
made deliberately now rather than discovered later.

## What this fixes

Defects found while working the corpus, all of the same class — the records not agreeing
with themselves — and all structurally prevented here:

- 243 placeholder stubs counted as coverage → the tree is generated from real samples
- 754 clean files filed under `during` → phase is a manifest field, and the generator
  enforces the rule the verifier now checks
- 22 samples under artifact ids no record declares → the view is generated *from* declared
  subjects, so an undeclared one cannot receive files
- 8 samples too large for git, present on one machine only → nothing is too large
- a sample recorded as held whose bytes were absent locally → `store.present` and
  `verify-store`'s `missing` state
- `aur-atomic-arch-packages` counting as one covered artifact while standing for ~1,800
  packages → an explicit subject makes coverage mean the same thing in every record
