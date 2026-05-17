# supplychain-attack-data

Welcome to the most comprehensive dataset on software supply-chain attacks in the world!

## Incident Criteria

This repository only includes cases where an open-source project or commercial product distributed malware knowingly or unknowingly. We also include edge cases, such as when an open-source project has shut down and an attacker later takes over its online presence.

- Malware uploaded to a random website with no relationship to the project or product
- Random USB keys found on a sidewalk
- Projects only known in the context of delivering malware (for example, a project created solely to demonstrate an attack)
- Typosquatting attacks

## Data

- Campaigns describe one bounded operation across multiple attacks. OSS campaigns live under `oss/campaigns/`; attacks link to them with `campaigns:`. Actor groups such as TeamPCP belong in `actor`, not as broad campaign records, and each attack should link to at most one campaign.
- Attacks describe one compromised trust boundary: a vendor, maintainer account, project organization, provider, registry account, release pipeline, or official distribution surface
- `id` is a stable machine identifier. Keep it lowercase, URL-safe, and durable; do not rewrite it just to improve display text
- `target.name` is the canonical attacked entity: the project, vendor, product, service, maintainer account, registry, or distribution surface whose trust boundary failed
- `artifact.name` and `artifact.package` identify concrete affected things: packages, plugins, actions, images, releases, installers, archives, update channels, or source trees. Use package names and official product names here, not prose
- `title` is the human headline. It should make sense as a timeline label and detail-page heading. Include the target and the compromise path, payload, or downstream impact. Keep it short, usually 5-9 words, with a hard cap of 90 characters and no sentence-ending punctuation. Do not put a full synopsis, date range, month, year, or every affected package in the title unless the date is needed to distinguish otherwise identical records.
- `synopsis` is the compact factual summary. Use 2 sentences normally, or 1 sentence when the event is simple, with a hard cap of 280 characters. State what happened and why it mattered; do not merely repeat the title. Prefer scope, delivery path, payload, or impact over color
- `story` is optional narrative detail for notable records. Use 3-4 paragraphs for attack method, delivery method, code or artifact changes, impact, discovery, and response details that would make the synopsis too dense. Write stories in a concise, technical, straightforward voice: short sentences, concrete nouns, active verbs, no hype, no metaphor, no invented drama
- `method.phase` is the lifecycle point where the malicious change entered the trusted path, such as `source`, `dependency`, `ci_cd`, or `distribution`. It is not the name or type of the service. A package registry, vendor download site, update server, CDN, GitHub Release, FTP server, app store, or physical media can all be `phase: distribution`
- `target.name` and `artifact.name` are proper names: the project, vendor, product, package, plugin, installer, source archive, update channel, or service that was attacked or served to users
- `target.kind` and `artifact.kind` are type labels: what sort of thing the name refers to, such as `library`, `application`, `firmware`, `package_registry`, `distribution_site`, `update_service`, `source_archive`, `binary_archive`, `installer`, or `ci_cd_action`
- `artifact.ecosystem` names the package or distribution ecosystem when there is one, such as `npm`, `pypi`, `rubygems`, `wordpress.org`, `docker`, `github_actions`, or `windows installer`
- Artifacts live under `artifacts:` inside an attack. Use them for concrete packages, plugins, actions, images, releases, installers, source archives, artifact-specific dates, hashes, and artifact-specific impact counts
- Targets and artifacts can include `website:` and `repo:` for official project, package, vendor, or product locations
- `locations:` records durable artifact locations only. Use `role: distribution` for the trusted path that served the affected artifact, and `role: mirror` for archived copies, sample pages, VirusTotal entries, or other places a copy can be found later. Do not store reachability or freshness status in canonical data
- `hashes:` records hashes of the artifact named by that artifact record. If a source reports a hash for an embedded file, payload, patch, or component rather than the whole artifact, store it under `indicators:` with a clear kind such as `file_sha256` and include the file name in the value
- `evidence:` records local files checked into this repository that support an artifact, such as clean and compromised extracts, diffs, patches, decoded payloads, or historical advisory text. Use `{kind, path, role}` with a relative path from the attack directory. Do not use URLs here; use `locations:` or `references:` for URLs
- `references:` records source pages as `{url, title}`. Include page titles when practical so generated pages have useful link text and old sources remain findable
- `versions` must contain only affected version identifiers, such as `1.2.3`, `1.2.3-alpha`, or `v1.2.3`, or explicit spaced ranges such as `1.2.0 - 1.2.4`. Use `fixed_versions` for known clean or remediated releases. Do not put package names, labels like `bad:` or `safe:`, constraints, or narrative context in either field
- Data is compiled into `oss_summary.csv` and `proprietary_summary.csv` as one row per attack. `oss_artifacts.csv` and `proprietary_artifacts.csv` are one row per affected artifact
- CSV and site artifacts can be refreshed using `make`
- OSS data is also periodically published into a Google Sheet for easy access: https://docs.google.com/spreadsheets/d/1C3SipbHjaOKVjxjKb85ICq68mgttI_un7p6XZ3xYNUc/edit?gid=1052022989#gid=1052022989

Example story format:

```yaml
story: |
  First paragraph: state how the attacker reached the trusted distribution path and what users received.

  Second paragraph: state how the malicious artifact was delivered and what code, build logic, package metadata, installer, update, or release asset changed.

  Third paragraph: state what the payload did, what systems or people were exposed, and why the impact mattered.

  Fourth paragraph, when useful: state discovery, remediation, attribution limits, or how this record relates to a broader campaign.
```

Example text field split:

```yaml
id: transmission-2016-03
target:
  name: transmission
title: Transmission macOS installer distributed KeRanger ransomware
synopsis: >-
  Attackers replaced the official Transmission 2.90 macOS disk image with a signed
  malicious build. Users following the trusted download path received KeRanger ransomware.
```

Example distribution modeling:

```yaml
method:
  phase: distribution

target:
  name: npm
  kind: package_registry

artifacts:
- package: event-stream
  ecosystem: npm
  kind: source_archive
  locations:
  - uri: https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz
    role: distribution
```

## Browse the data

For graphs and an easy-to-read view of the data, see the compendium: https://isotope13.ai/compendium/

To the best of my knowledge, the OSS data is complete. If you know of any cases where an open-source project distributed malware, please open an issue. Proprietary data is limited as many commercial attacks go unreported.

## PR's welcome!

This project is a work in progress. PR's welcome!
