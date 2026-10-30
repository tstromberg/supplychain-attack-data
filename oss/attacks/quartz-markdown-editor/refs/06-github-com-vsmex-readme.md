# VSMEx

A collection tool and dataset of malicious VS Code extensions removed by Microsoft.

Presented at [CODASPY 2026](https://www.codaspy.org/2026/) — June 23–25, Frankfurt am Main.

```bibtex
@inproceedings{Alachkar2026VSMEx,
  title     = {VSMEx: A Collection Tool and a Dataset of Malicious VS Code Extensions: Data/Toolset Paper},
  author    = {Alachkar, Kotaiba and Gaastra, Dirk and Gadyatskaya, Olga and Barbaro, Eduardo and van Eeten, Michel and Zhauniarovich, Yury},
  booktitle = {Proceedings of the Sixteenth ACM Conference on Data and Application Security and Privacy},
  pages     = {138–144},
  year      = {2026},
  url       = {https://doi.org/10.1145/3800506.3803487},
  address   = {New York, NY, USA},
  doi       = {10.1145/3800506.3803487},
  isbn      = {9798400725623},
  keywords  = {vs code, malicious extensions, dataset, collection tool},
  location  = {Germany},
  numpages  = {7},
  publisher = {Association for Computing Machinery},
  series    = {CODASPY '26},
}
```

## Dataset access

The VSIX packages and full metadata are not publicly available to prevent misuse. Access is provided to approved institutional researchers via [SURFfilesender](https://www.surf.nl/en/services/surffilesender).

To request access, email from an institutional address with your name, institution, and intended use.

- Dr. Yury Zhauniarovich — y.zhauniarovich [at] tudelft [dot] nl
- Kotaiba Alachkar — k.alachkar [at] tudelft [dot] nl

## Contents

### Public (this repo)

- `metadata/msft_vscode_flagged_extensions.csv` — one row per flagged extension
- `metadata/vsmex_metadata.csv` — one row per captured (extension, version) with sha256, size, ratings, etc.
- `stats.json` — live dataset statistics (read by the [project page](https://kalachkar.github.io/vsmex/))

### CSV schemas

**msft_vscode_flagged_extensions.csv**: `source`, `checked_date`, `extension_identifier`, `msft_classification_type`, `msft_removed_date`, `captured`, `version_count`, `latest_version`, `capture_date`.

**vsmex_metadata.csv**: `captured_date`, `source`, `msft_classification_type`, `extension_identifier`, `publisher_name`, `version`, `artifact`, `sha256`, `size_mb`, `published_date`, `last_updated_date`, `verified_publisher`, `installation_count`, `average_rating`, `rating_count`, `categories`, `repository_url`, `flags`, `engines_vscode`, `exists_in_dataset`.

### Tool

- `tool/crawler.py` — crawls the VS Code Marketplace, stores new VSIX files locally
- `tool/vsmex.py` — reads Microsoft's flagged lists, captures extensions to the dataset, syncs metadata to this repo
- `tool/config.py` — shared configuration

Previous Azure-based versions are archived in `tool/v1-azure/`.

## Running

Requires Python 3.11+ (tested on 3.14).

```bash
pip install -r tool/requirements.txt
```

Set environment variables in `~/.vsmex_env`:
```bash
export GITHUB_PAT="ghp_your_fine_grained_pat"
export GITHUB_USERNAME="your-github-username"
export VSMEX_BASE_DIR="/path/to/vsmex"
```

Source it and run:
```bash
. ~/.vsmex_env
python3 tool/crawler.py   # fetch new VSIXs from marketplace
python3 tool/vsmex.py     # sync Microsoft's flagged lists → dataset + metadata
```

For cron: `. ~/.vsmex_env && cd /path/to/vsmex/tool && python3 crawler.py`

## License

See [LICENSE](LICENSE).

## Acknowledgements

We thank [Marc Ohm](https://github.com/dasfreak/Backstabbers-Knife-Collection) for the Backstabbers' Knife Collection, which provided initial malicious VS Code extension samples used in this dataset, and [Karlo Zanki](https://www.reversinglabs.com) from ReversingLabs for sharing additional samples.
