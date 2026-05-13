# supplychain-attack-data

Welcome to the most comprehensive dataset on software supply-chain attacks in the world!

## Incident Criteria

This repository only includes cases where an open-source project or commercial product distributed malware knowingly or unknowingly. We also include edge cases, such as when an open-source project has shut down and an attacker later takes over its online presence.

- Malware uploaded to a random website with no relationship to the project or product
- Random USB keys found on a sidewalk
- Projectsonly known in the context of delivering malware (for example, a project created solely to demonstrate an attack)
- Typosquatting attacks

## Data

- Campaigns describe shared actor, tooling, infrastructure, and timeline across multiple attacks. OSS campaigns live under `oss/campaigns/`; attacks link to them with `campaigns:`
- Attacks describe one compromised trust boundary: a vendor, maintainer account, project organization, provider, registry account, release pipeline, or official distribution surface
- Affected artifacts live under `affected_artifacts:` inside an attack. Use them for concrete packages, plugins, actions, images, releases, installers, source archives, artifact-specific dates, hashes, and artifact-specific impact counts
- `versions` must contain only affected version identifiers, such as `1.2.3`, `1.2.3-alpha`, or `v1.2.3`. Use `fixed_versions` for known clean or remediated releases. Do not put package names, labels like `bad:` or `safe:`, ranges, or narrative context in either field
- Data is compiled into `oss_summary.csv` and `proprietary_summary.csv` as one row per attack. `oss_artifacts.csv` and `proprietary_artifacts.csv` are one row per affected artifact; records without `affected_artifacts` are treated as single-artifact attacks during CSV generation
- CSV and site artifacts can be refreshed using `make`
- OSS data is also periodically published into a Google Sheet for easy access: https://docs.google.com/spreadsheets/d/1C3SipbHjaOKVjxjKb85ICq68mgttI_un7p6XZ3xYNUc/edit?gid=1052022989#gid=1052022989

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
