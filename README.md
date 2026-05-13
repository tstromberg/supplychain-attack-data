# supplychain-attack-data

Welcome to the most comprehensive dataset on software supply-chain attacks in the world!

## Incident Criteria

This repository only includes cases where an open-source project or commercial product distributed malware knowingly or unknowingly. We also include edge cases, such as when an open-source project has shut down and an attacker later takes over its online presence.

- Malware uploaded to a random website with no relationship to the project or product
- Random USB keys found on a sidewalk
- Projects only known in the context of delivering malware (for example, a project created solely to demonstrate an attack)
- Typosquatting attacks

## Data

- Campaigns describe shared actor, tooling, infrastructure, and timeline across multiple attacks. OSS campaigns live under `oss/campaigns/`; attacks link to them with `campaigns:`
- Attacks describe one compromised trust boundary: a vendor, maintainer account, project organization, provider, registry account, release pipeline, or official distribution surface
- `title` is the short display name. `synopsis` is a 40-110 word summary focused on what happened and why it mattered. Optional `story` is a longer 2-4 paragraph block for chronology, impact, tradecraft, discovery, and response details that would make the synopsis too dense
- Artifacts live under `artifacts:` inside an attack. Use them for concrete packages, plugins, actions, images, releases, installers, source archives, artifact-specific dates, hashes, and artifact-specific impact counts
- Targets and artifacts can include `website:` and `repo:` for official project, package, vendor, or product locations
- `locations:` records durable artifact locations only. Use `role: distribution` for the trusted path that served the affected artifact, and `role: mirror` for archived copies, sample pages, VirusTotal entries, or other places a copy can be found later. Do not store reachability or freshness status in canonical data
- `references:` records source pages as `{url, title}`. Include page titles when practical so generated pages have useful link text and old sources remain findable
- `versions` must contain only affected version identifiers, such as `1.2.3`, `1.2.3-alpha`, or `v1.2.3`, or explicit spaced ranges such as `1.2.0 - 1.2.4`. Use `fixed_versions` for known clean or remediated releases. Do not put package names, labels like `bad:` or `safe:`, constraints, or narrative context in either field
- Data is compiled into `oss_summary.csv` and `proprietary_summary.csv` as one row per attack. `oss_artifacts.csv` and `proprietary_artifacts.csv` are one row per affected artifact
- CSV and site artifacts can be refreshed using `make`
- OSS data is also periodically published into a Google Sheet for easy access: https://docs.google.com/spreadsheets/d/1C3SipbHjaOKVjxjKb85ICq68mgttI_un7p6XZ3xYNUc/edit?gid=1052022989#gid=1052022989

Example story format:

```yaml
story: |
  First paragraph: how the attacker reached the trusted distribution path and what users received.

  Second paragraph: what the payload did, what systems or people were exposed, and why the impact mattered.

  Third paragraph, when useful: discovery, remediation, attribution limits, or how this record relates to a broader campaign.
```

## OSS Pwn Count

* 56 OSS projects
* 59 incidents

To the best of my knowledge, this data is complete, but if you know of any cases where an open-source project distributed malware, please open an issue.

![OSS supply-chain compromises over time](assets/chart.png)
![OSS supply-chain compromises: insertion point](assets/where.png)
![OSS supply-chain compromises: insertion point](assets/attack_vector.png)
![OSS supply-chain compromises: insertion point](assets/impact.png)

## Proprietary Pwn Count

* 45 products & incidents

Note: Available data is limited as many commercial attacks go unreported.

## PR's welcome!

This project is a work in progress. PR's welcome!
