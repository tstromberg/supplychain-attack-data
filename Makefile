.PHONY: all compile validate run clean site serve deploy samples-inventory samples-verify samples-npm-mirror missing-before missing-during missing-after refs artifacts artifacts-verify sync sync-dry snapshot

all: compile run site

compile: out/yaml2csv

# Validate without overwriting generated CSVs. Any validation error fails this target.
validate: out/yaml2csv
	@validation_status=0; \
	for scope in oss proprietary; do \
		YAML2CSV_STRICT=1 ./out/yaml2csv "$$scope" > /dev/null || validation_status=1; \
	done; \
	exit $$validation_status

out/yaml2csv: $(wildcard ./cmd/yaml2csv/*.go)
	@mkdir -p out
	(cd cmd/yaml2csv && go build -o ../../out/yaml2csv .)

run: out/yaml2csv
	(cd oss && ../out/yaml2csv > ../oss_summary.csv)
	(cd proprietary && ../out/yaml2csv > ../proprietary_summary.csv)
	(cd oss && ../out/yaml2csv --artifacts > ../oss_artifacts.csv)
	(cd proprietary && ../out/yaml2csv --artifacts > ../proprietary_artifacts.csv)

site:
	npm install
	npm run build

serve:
	@command -v npx >/dev/null 2>&1 || { echo "npx not found. Please install Node.js and npm."; exit 1; }
	@npx eleventy --version >/dev/null 2>&1 || { echo "Eleventy not found. Installing dependencies..."; npm install; }
	npm run serve

deploy: site
	@command -v npx >/dev/null 2>&1 || { echo "npx not found. Please install Node.js and npm."; exit 1; }
	@npx gh-pages -d _site

samples-inventory:
	node tools/acquire-oss-samples.js --no-before

samples-verify:
	node tools/verify-oss-samples.js

# Recovers npm releases npm has unpublished from the caching registry mirrors that
# still serve what they cached while those releases were live.
samples-npm-mirror:
	node tools/acquire-npm-mirror.js --phase during

# Reports the attacks still missing a sample for one collection phase. An attack
# counts as covered only when every artifact its record names has one.
missing-during:
	node tools/missing-samples.js --phase during --out MUST-FIND.md

missing-before:
	node tools/missing-samples.js --phase before --out MUST-FIND-BEFORE.md

missing-after:
	node tools/missing-samples.js --phase after --out MUST-FIND-AFTER.md

# The artifact tree: payload bytes, generated from the records in this repository.
# It lives outside git because the bytes are too large for it; BUILD.yaml in the tree
# pins the commit it was produced from.
TREE ?= $(HOME)/data/supplychain-attack-data
BUCKET ?= r2:isotope13-compendium

# R2 has no object versioning, so a replaced or deleted object is simply gone. The tree is
# not a cache -- for payload bytes it is one of only two copies -- so `sync` keeps what it
# displaces instead of dropping it. Each run moves replaced and deleted objects into a
# dated prefix in this second bucket, which is the closest thing R2 offers to a version
# history. Create it once: `rclone mkdir $(BACKUP)`.
BACKUP ?= r2:isotope13-compendium-bak

# A frozen full copy of the tree, taken once and then left alone. `sync` protects against
# a bad build displacing good objects; this protects against losing the live bucket. It is
# deliberately not part of `sync` -- a snapshot that is refreshed on every publish is not a
# snapshot. Retake it by hand when the corpus has moved enough to be worth another copy.
SNAPSHOT ?= r2:isotope13-compendium-attic

artifacts:
	node tools/build-artifacts.js --apply --out $(TREE)

# Every sample the records claim, against the bytes actually in the tree. Run this
# before sync: it is the only thing standing between a manifest claim and the file
# it names once the bytes live outside git.
artifacts-verify:
	node tools/verify-store.js --out $(TREE)

# Shows what sync would do, and does none of it. Mirrors sync's flags so the preview is
# of the real thing: displaced objects are reported as moved to the backup bucket, not
# as deletions.
sync-dry:
	rclone sync --dry-run --progress --checksum \
		--backup-dir "$(BACKUP)/$$(date -u +%Y-%m-%dT%H%M%SZ)" $(TREE) $(BUCKET)

# Publishes the tree. It runs only after verify-store agrees the tree is complete --
# otherwise a half-built tree would displace good objects. --checksum compares digests
# rather than timestamps, which is what this corpus is about, and --backup-dir means
# nothing is destroyed: what this run replaces or removes lands in the backup bucket,
# under the time it happened.
sync: artifacts-verify
	rclone sync --progress --checksum --transfers 8 \
		--backup-dir "$(BACKUP)/$$(date -u +%Y-%m-%dT%H%M%SZ)" $(TREE) $(BUCKET)

# Server-side copy, so the bytes never leave Cloudflare. Additive: it never deletes from
# the snapshot, so an older copy survives alongside a newer one.
snapshot: artifacts-verify
	rclone copy --progress --checksum --transfers 8 $(BUCKET) $(SNAPSHOT)

clean:
	@echo "Cleaning up generated files..."
	rm -f out/yaml2csv oss_summary.csv proprietary_summary.csv oss_artifacts.csv proprietary_artifacts.csv
	@rmdir --ignore-fail-on-non-empty out

# Archives every page the records cite, into a refs/ directory beside each
# record. Re-running only fetches what is missing or previously failed.
refs:
	node tools/archive-references.js
