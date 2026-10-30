import yaml
import glob
import os

files = glob.glob('/Users/t/src/supplychain-attack-data/*/attacks/*/meta.yaml')
bad_files = []

for f in files:
    with open(f, 'r') as file:
        data = yaml.safe_load(file)
        if not data: continue
        for entry in data:
            if 'artifacts' in entry:
                for idx, artifact in enumerate(entry['artifacts']):
                    has_version_or_purl = 'versions' in artifact or 'version' in artifact or 'purl' in artifact
                    has_hash = 'hashes' in artifact or 'hash' in artifact
                    if not has_version_or_purl and not has_hash:
                        bad_files.append(f)
                        break

for b in sorted(set(bad_files)):
    print(b)
