# Research and editorial guidance

Read this file when adding or revising compendium records, including records under
`oss/` and `proprietary/`. It is the shared guidance for this work; private agent
memory must not be the only place an editorial decision is recorded.

Use [oss_prompt.txt](oss_prompt.txt) or
[proprietary_prompt.txt](proprietary_prompt.txt) for the relevant research scope,
and [SAMPLE_ACQUISITION.md](../SAMPLE_ACQUISITION.md) for sample collection and
provenance.

## Incident scope

Include established upstream projects or commercial products that distributed
malicious code through their source, build, release, or official distribution
path. Exclude typosquats, attacker-created projects, vulnerabilities without
malicious distribution, and unmerged malicious contributions. Identify each
compromised trust boundary separately.

## Storytelling

This file is the shared authority for editorial guidance in OSS attacks, campaigns,
and proprietary incidents. Keep the research prompts linked to it.
Claude Code's private project memory recorded a May 22, 2026 change to
KrebsOnSecurity-style reporting that superseded the earlier Pike/Venema preference.
That change applies here too: accessible, well-attributed reporting with a clear
narrative, written in our own words.

Write **3-4 substantive paragraphs**, normally four when the reporting supports
them. A synopsis, a sequence of one-sentence fragments, or a list of indicators
does not substitute for a story. Do not pad thin evidence to reach a paragraph
count; identify what remains unknown and seek additional reporting when needed.
Every article must also include a `pull_quote` with nonempty `text` and an `after`
position naming a story paragraph (counting from 1). Select a useful passage from
the story; a pull quote is not an excuse to invent a quotation from a source.

- **Lead with the event and its stakes.** Tell the reader what happened, who was
  affected, and why it mattered. Start with the news, then explain the sequence
  that led to it. Avoid opening with a package coordinate or a catalogue of files.
- **Set the scene in plain English.** Explain what the project or product does,
  who uses it, and which normal installation, update, or development activity
  exposed those users. A security engineer should not need prior knowledge of
  this particular ecosystem to follow the account.
- **Explain the mechanism as a causal sequence.** Show how access to a maintainer
  account, source repository, build process, or distribution service became code
  that users received or ran. Include versions, paths, commands, and timestamps
  when they explain that sequence. Keep exhaustive indicators in structured fields.
- **Attribute findings in the prose.** Name the researchers, firms, or maintainers
  responsible for consequential findings. Distinguish vendor confirmation,
  researcher observations, our sample inspection, and inference. References at
  the bottom do not replace attribution in the story.
- **Close with the response and remaining consequences.** Explain what was
  removed, fixed, revoked, or left exposed, where the sources establish it.
  Distinguish download counts from confirmed victims and malicious source changes
  from poisoned releases. State gaps in attribution or recovery without inventing
  a resolution or a generic lesson.

Use connected prose, past tense, and third person. Let each paragraph advance the
account instead of repeating the synopsis. Prefer natural dates such as "On
October 8"; use exact timestamps when an exposure window matters. Keep the
technical substance, but explain why each detail belongs in the story.

Avoid hype, marketing language, invented motives, unsupported characterizations,
fabricated quotations, theatrical punchlines, and choppy bullet lists inside the
story. A characterization or quotation is appropriate only when the cited
evidence supports it. Do not turn uncertainty into a confident claim for the sake
of a smoother narrative.

Before considering an article finished, check that a reader can explain what the
software does, how its trusted upstream path failed, what users encountered, who
established those facts, and what happened afterward. Check the paragraph count
and read the story aloud for flow. Passing the YAML validator alone does not make
an article complete.

The outline below is a guide, not a template to repeat verbatim across incidents:

```yaml
story: |
  First paragraph: lead with the event, the affected users, and the stakes; attribute the central finding.

  Second paragraph: explain the software and the normal trusted path that brought users into contact with the attack.

  Third paragraph: connect the upstream compromise to the malicious behavior and its consequences, using concrete technical details.

  Fourth paragraph: describe the response, remaining exposure, and limits of what the reporting establishes.
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

## Current validator limits

The implementation is in [cmd/yaml2csv/main.go](../cmd/yaml2csv/main.go).
These are the current mechanical checks, not a substitute for editorial review:

| Field | Validator limit |
| --- | --- |
| Title | At most 90 Unicode characters; no final `.`, `!`, or `?` |
| Synopsis | At most 280 Unicode characters; 1–2 sentences |
| Story | Required; 2–4 paragraphs separated by blank lines; no word or character limit |
| Notes | At most 4 notes per validated list; at most 240 Unicode characters per note |
| Pull quote | Required; nonempty text; at most 40 words and 2 sentences |
| Pull-quote caption | At most 8 words |
| Pull-quote position | From 1 through the story paragraph count |

The editorial target for new articles is **3–4 substantive story paragraphs**.
The validator enforces a minimum of two paragraphs and a pull quote for both
attacks and campaigns. It does not check reporting depth, attribution, or
narrative flow. Run `make validate` for a strict check of the complete dataset
without overwriting CSVs. Ordinary CSV generation logs validation issues;
`YAML2CSV_STRICT=1` makes validation errors fail the command.

## Record structure

- Campaigns describe one bounded operation across multiple attacks. OSS campaigns live under `oss/campaigns/`; attacks link to them with `campaigns:`. Actor groups such as TeamPCP belong in `actor`, not as broad campaign records, and each attack should link to at most one campaign.
- Attacks describe one compromised trust boundary: a vendor, maintainer account, project organization, provider, registry account, release pipeline, or official distribution surface
- `id` is a stable machine identifier. Keep it lowercase, URL-safe, and durable; do not rewrite it just to improve display text
- `target.name` is the canonical attacked entity: the project, vendor, product, service, maintainer account, registry, or distribution surface whose trust boundary failed
- `artifact.name` and `artifact.package` identify concrete affected things: packages, plugins, actions, images, releases, installers, archives, update channels, or source trees. Use package names and official product names here, not prose
- `title` is the human headline. It should make sense as a timeline label and detail-page heading. Include the target and the compromise path, payload, or downstream impact. Keep it short, usually 5-9 words, with a hard cap of 90 characters and no sentence-ending punctuation. Do not put a full synopsis, date range, month, year, or every affected package in the title unless the date is needed to distinguish otherwise identical records.
- `synopsis` is the compact factual summary. Use 2 sentences normally, or 1 sentence when the event is simple, with a hard cap of 280 characters. State what happened and why it mattered; do not merely repeat the title. Prefer scope, delivery path, payload, or impact over color
- `story` is the article, distinct from the compact synopsis. Newly researched entries should include 3-4 substantive paragraphs following the storytelling guidance above. All records must satisfy the two-paragraph minimum and include a pull quote.
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

