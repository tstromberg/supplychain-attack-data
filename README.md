# supplychain-attack-data

Welcome to the most comprehensive dataset on software supply-chain attacks in the world!

## Incident Criteria

This repository only includes cases where an open-source project or commercial product distributed malware knowingly or unknowingly. We also include edge cases, such as when an open-source project has shut down and an attacker later takes over its online presence.

- Malware uploaded to a random website with no relationship to the project or product
- Random USB keys found on a sidewalk
- Projects only known in the context of delivering malware (for example, a project created solely to demonstrate an attack)
- Typosquatting attacks

## Data

OSS attacks and campaigns live under `oss/`; commercial incidents live under
`proprietary/`. Each attack record contains its target, narrative, affected
artifacts, and references in `meta.yaml`.

`oss_summary.csv` and `proprietary_summary.csv` contain one row per attack.
`oss_artifacts.csv` and `proprietary_artifacts.csv` contain one row per affected
artifact. `make` refreshes the CSVs and site.

OSS data is also periodically published to a [Google Sheet](https://docs.google.com/spreadsheets/d/1C3SipbHjaOKVjxjKb85ICq68mgttI_un7p6XZ3xYNUc/edit?gid=1052022989#gid=1052022989).

## Browse the data

For graphs and an easy-to-read view of the data, see the compendium: https://isotope13.ai/compendium/

To the best of my knowledge, the OSS data is complete. If you know of any cases where an open-source project distributed malware, please open an issue. Proprietary data is limited as many commercial attacks go unreported.

## PR's welcome!

This project is a work in progress. PR's welcome!
