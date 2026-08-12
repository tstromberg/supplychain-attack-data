.PHONY: all compile run clean site serve deploy samples-inventory samples-verify refs

all: compile run site

compile: out/yaml2csv

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

clean:
	@echo "Cleaning up generated files..."
	rm -f out/yaml2csv oss_summary.csv proprietary_summary.csv oss_artifacts.csv proprietary_artifacts.csv
	@rmdir --ignore-fail-on-non-empty out

# Archives every page the records cite, into a refs/ directory beside each
# record. Re-running only fetches what is missing or previously failed.
refs:
	node tools/archive-references.js
