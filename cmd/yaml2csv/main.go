package main

import (
	"encoding/csv"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Headers for CSV output
var csvHeaders = []string{
	"name", "title", "repo", "synopsis", "year", "start_date", "end_date",
	"attribution_type", "component_type", "lang", "cause", "motive",
	"transitive", "insertion_phase", "impact_type", "impact_user_count",
	"references", "versions", "commits", "historical_artifacts", "current_artifacts",
	"domain", "domain_type", "artifact_type", "hashes",
}

// AttackEntry defines the structure for unmarshalling the meta.yaml files
type AttackEntry struct {
	Name                string   `yaml:"name"`
	Title               string   `yaml:"title"`
	Repo                string   `yaml:"repo"`
	Synopsis            string   `yaml:"synopsis"`
	StartDate           string   `yaml:"start_date"`
	EndDate             string   `yaml:"end_date"`
	AttributionType     string   `yaml:"attribution_type"`
	ComponentType       string   `yaml:"component_type"`
	Lang                string   `yaml:"lang"`
	Cause               string   `yaml:"cause"`
	Motive              string   `yaml:"motive"`
	Transitive          bool     `yaml:"transitive"`
	InsertionPhase      string   `yaml:"insertion_phase"`
	ImpactType          string   `yaml:"impact_type"`
	ImpactUserCount     int      `yaml:"impact_user_count"`
	References          []string `yaml:"references"`
	Versions            []string `yaml:"versions"`
	Commits             []string `yaml:"commits"`
	HistoricalArtifacts []string `yaml:"historical_artifacts"`
	CurrentArtifacts    []string `yaml:"current_artifacts"`
	Domain              string   `yaml:"domain"`
	DomainType          string   `yaml:"domain_type"`
	ArtifactType        string   `yaml:"artifact_type"`
	Hashes              []string `yaml:"hashes"`
	SourcePath          string   `yaml:"-"`
}

type validationIssue struct {
	Severity string
	Field    string
	Value    string
	Path     string
	Name     string
	Message  string
}

var (
	fullDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	hashPattern     = regexp.MustCompile(`^(md5|sha1|sha256|sha384|sha512):([0-9a-fA-F]+)$`)
	partialDate     = regexp.MustCompile(`^\d{4}(-\d{2})?$`)
)

func main() {
	// Get search directory from args or use current directory
	rootDir := "."
	if len(os.Args) > 1 {
		rootDir = os.Args[1]
	}

	absRootDir, err := filepath.Abs(rootDir)
	if err != nil {
		log.Fatalf("Error: Could not determine absolute path for %q: %v", rootDir, err)
	}

	log.Printf("Info: Searching for meta.yaml files in: %s", absRootDir)

	// Collect all entries from all meta.yaml files
	var allEntries []AttackEntry
	count := 0

	err = filepath.WalkDir(absRootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "meta.yaml" {
			return nil
		}

		// log.Printf("Info: Processing file: %s", path)

		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Warning: Could not read %s: %v. Skipping.", path, err)
			return nil
		}

		var entries []AttackEntry
		if err := yaml.Unmarshal(data, &entries); err != nil {
			log.Printf("Warning: Could not parse %s: %v. Skipping.", path, err)
			return nil
		}

		for i := range entries {
			entries[i].SourcePath = path
		}
		allEntries = append(allEntries, entries...)
		count += len(entries)
		return nil
	})
	if err != nil {
		log.Fatalf("Error: Failed walking directory: %v", err)
	}

	if count == 0 {
		log.Println("Info: No meta.yaml files found or successfully processed.")
		return
	}

	validateEntries(allEntries)

	// Sort entries by start_date
	sort.Slice(allEntries, func(i, j int) bool {
		// Empty dates go last
		if allEntries[i].StartDate == "" {
			return false
		}
		if allEntries[j].StartDate == "" {
			return true
		}

		// Try parsing as dates first
		date1, err1 := time.Parse("2006-01-02", allEntries[i].StartDate)
		date2, err2 := time.Parse("2006-01-02", allEntries[j].StartDate)
		if err1 == nil && err2 == nil {
			return date1.Before(date2)
		}

		// Fall back to string comparison
		return allEntries[i].StartDate < allEntries[j].StartDate
	})

	// Write sorted entries to CSV
	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()

	if err := writer.Write(csvHeaders); err != nil {
		log.Fatalf("Error: Failed to write CSV headers: %v", err)
	}

	for _, entry := range allEntries {
		row := entryToRow(entry)
		if err := writer.Write(row); err != nil {
			log.Printf("Warning: Error writing row: %v", err)
		}
	}

	log.Printf("Info: CSV generation complete. Processed %d entries.", count)
}

func validateEntries(entries []AttackEntry) {
	issues := collectValidationIssues(entries)
	errorCount := 0
	for _, issue := range issues {
		if issue.Severity == "error" {
			errorCount++
		}
		log.Printf("Validation %s: %s", issue.Severity, issue.String())
	}

	if errorCount > 0 && os.Getenv("YAML2CSV_STRICT") == "1" {
		log.Fatalf("Error: validation failed with %d error(s)", errorCount)
	}
}

func collectValidationIssues(entries []AttackEntry) []validationIssue {
	var issues []validationIssue

	validInsertionPhase := map[string]bool{
		"CI/CD":        true,
		"dependency":   true,
		"distribution": true,
		"production":   true,
		"runtime":      true,
		"source":       true,
	}
	insertionPhaseAliases := map[string]string{
		"build script (makefile)": "CI/CD",
		"ci/cd":                   "CI/CD",
		"cicd":                    "CI/CD",
	}
	validComponentType := valueSet(
		"Application", "Build Tool", "CDN", "CI/CD plugin", "CLI Tool",
		"Compiler", "Daemon", "Distribution", "Driver", "Extension",
		"Firmware", "Game", "Game mod", "Hardware", "Library", "OS",
		"OS / Application", "Package Manager", "Plugin", "Repository",
		"Script",
	)
	validDomainType := valueSet(
		"CDN", "CDN host", "code distribution", "code host", "container host",
		"package host", "product host", "project download host", "repository",
		"repository/container registry", "source host", "vendor",
	)
	validArtifactType := valueSet(
		"GitHub Action", "OCI image", "action", "application", "binary archive",
		"dependency file", "extension", "extension package", "firmware",
		"floppy disk", "hardware", "package registry", "plugin",
		"release binary/container image/action", "revision control system",
		"script", "source archive", "source archive/container image",
		"source code", "source repository", "tar archive", "wheel",
	)
	validAttributionType := valueSet(
		"APT group", "Accidental", "Advanced Persistent Threat",
		"Adware bundlers", "Author", "Chinese-speaking actor",
		"Commercial company", "Compromised Dependency", "Cybercriminal",
		"Cybercriminal Gang", "Cybercriminal group", "Individual",
		"Individual Hacker", "Insider", "Nation-state", "New maintainer",
		"New owner", "TeamPCP", "Third Party", "Threat Actor", "Unknown",
		"Unknown attacker",
	)

	for _, entry := range entries {
		issues = append(issues, validateRequiredFields(entry)...)
		issues = append(issues, validateSynopsis(entry)...)
		issues = append(issues, validateDateField(entry, "start_date", entry.StartDate)...)
		issues = append(issues, validateDateField(entry, "end_date", entry.EndDate)...)
		issues = append(issues, validateHashes(entry)...)

		if entry.InsertionPhase != "" && !validInsertionPhase[entry.InsertionPhase] {
			msg := "not in canonical insertion_phase set"
			if canonical, ok := insertionPhaseAliases[normalizeValue(entry.InsertionPhase)]; ok {
				msg = fmt.Sprintf("prefer %q", canonical)
			}
			issues = append(issues, validationIssue{
				Severity: "error",
				Field:    "insertion_phase",
				Value:    entry.InsertionPhase,
				Path:     entry.SourcePath,
				Name:     entry.Name,
				Message:  msg,
			})
		}

		if strings.Contains(entry.ImpactType, "/") {
			issues = append(issues, validationIssue{
				Severity: "error",
				Field:    "impact_type",
				Value:    entry.ImpactType,
				Path:     entry.SourcePath,
				Name:     entry.Name,
				Message:  "use comma-separated values instead of slash-combined labels",
			})
		}

		issues = append(issues, validateEnumField(entry, "component_type", entry.ComponentType, validComponentType)...)
		issues = append(issues, validateEnumField(entry, "domain_type", entry.DomainType, validDomainType)...)
		issues = append(issues, validateEnumField(entry, "artifact_type", entry.ArtifactType, validArtifactType)...)
		issues = append(issues, validateEnumField(entry, "attribution_type", entry.AttributionType, validAttributionType)...)
	}

	issues = append(issues, detectCaseVariants(entries, "impact_type", func(entry AttackEntry) []string {
		return splitListField(entry.ImpactType)
	})...)
	issues = append(issues, detectCaseVariants(entries, "component_type", func(entry AttackEntry) []string {
		return singleValue(entry.ComponentType)
	})...)
	issues = append(issues, detectCaseVariants(entries, "artifact_type", func(entry AttackEntry) []string {
		return singleValue(entry.ArtifactType)
	})...)
	issues = append(issues, detectCaseVariants(entries, "domain_type", func(entry AttackEntry) []string {
		return singleValue(entry.DomainType)
	})...)
	issues = append(issues, detectCaseVariants(entries, "attribution_type", func(entry AttackEntry) []string {
		return singleValue(entry.AttributionType)
	})...)

	return issues
}

func validateRequiredFields(entry AttackEntry) []validationIssue {
	required := map[string]string{
		"name":             entry.Name,
		"title":            entry.Title,
		"synopsis":         entry.Synopsis,
		"start_date":       entry.StartDate,
		"end_date":         entry.EndDate,
		"attribution_type": entry.AttributionType,
		"component_type":   entry.ComponentType,
		"cause":            entry.Cause,
		"motive":           entry.Motive,
		"insertion_phase":  entry.InsertionPhase,
		"impact_type":      entry.ImpactType,
		"domain_type":      entry.DomainType,
		"artifact_type":    entry.ArtifactType,
	}

	var issues []validationIssue
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, validationIssue{
				Severity: "error",
				Field:    field,
				Path:     entry.SourcePath,
				Name:     entry.Name,
				Message:  "required field is empty",
			})
		}
	}
	return issues
}

func validateSynopsis(entry AttackEntry) []validationIssue {
	wordCount := len(strings.Fields(entry.Synopsis))
	if wordCount >= 40 && wordCount <= 110 {
		return nil
	}
	return []validationIssue{{
		Severity: "error",
		Field:    "synopsis",
		Value:    strconv.Itoa(wordCount),
		Path:     entry.SourcePath,
		Name:     entry.Name,
		Message:  "synopsis must be between 40 and 110 words",
	}}
}

func validateDateField(entry AttackEntry, field, value string) []validationIssue {
	if value == "" {
		return nil
	}
	if value == "Ongoing" {
		return nil
	}
	if fullDatePattern.MatchString(value) {
		if _, err := time.Parse("2006-01-02", value); err == nil {
			return nil
		}
	}
	if _, err := time.Parse(time.RFC3339, value); err == nil {
		return nil
	}

	msg := "use YYYY-MM-DD, RFC3339 timestamp, Ongoing, or empty"
	if value == "Unknown" || partialDate.MatchString(value) {
		msg = "partial/unknown dates sort poorly; use a full YYYY-MM-DD date"
	}

	return []validationIssue{{
		Severity: "error",
		Field:    field,
		Value:    value,
		Path:     entry.SourcePath,
		Name:     entry.Name,
		Message:  msg,
	}}
}

func validateHashes(entry AttackEntry) []validationIssue {
	expectedLengths := map[string]int{
		"md5":    32,
		"sha1":   40,
		"sha256": 64,
		"sha384": 96,
		"sha512": 128,
	}

	var issues []validationIssue
	for _, hash := range entry.Hashes {
		hash = strings.TrimSpace(hash)
		match := hashPattern.FindStringSubmatch(hash)
		if len(match) != 3 {
			issues = append(issues, hashIssue(entry, hash, "hash must use md5:, sha1:, sha256:, sha384:, or sha512: followed by hexadecimal digest"))
			continue
		}

		algorithm := strings.ToLower(match[1])
		digest := match[2]
		if len(digest) != expectedLengths[algorithm] {
			issues = append(issues, hashIssue(entry, hash, fmt.Sprintf("%s digest must be %d hexadecimal characters", algorithm, expectedLengths[algorithm])))
			continue
		}
		if looksPlaceholderHash(strings.ToLower(digest)) {
			issues = append(issues, hashIssue(entry, hash, "digest looks like placeholder data"))
		}
	}
	return issues
}

func hashIssue(entry AttackEntry, value, message string) validationIssue {
	return validationIssue{
		Severity: "error",
		Field:    "hashes",
		Value:    value,
		Path:     entry.SourcePath,
		Name:     entry.Name,
		Message:  message,
	}
}

func looksPlaceholderHash(digest string) bool {
	if strings.Contains(digest, "abcdef1234567890") || strings.Contains(digest, "123abc456def7890") {
		return true
	}
	for _, char := range digest {
		if strings.Count(digest, string(char)) == len(digest) {
			return true
		}
	}
	return false
}

func validateEnumField(entry AttackEntry, field, value string, allowed map[string]bool) []validationIssue {
	if value == "" || allowed[value] {
		return nil
	}
	return []validationIssue{{
		Severity: "error",
		Field:    field,
		Value:    value,
		Path:     entry.SourcePath,
		Name:     entry.Name,
		Message:  "not in canonical value set",
	}}
}

func detectCaseVariants(entries []AttackEntry, field string, values func(AttackEntry) []string) []validationIssue {
	type variantCount map[string]int

	seen := map[string]variantCount{}
	for _, entry := range entries {
		for _, value := range values(entry) {
			if value == "" {
				continue
			}
			key := normalizeValue(value)
			if key == "" {
				continue
			}
			if seen[key] == nil {
				seen[key] = variantCount{}
			}
			seen[key][value]++
		}
	}

	var issues []validationIssue
	for _, variants := range seen {
		if len(variants) < 2 {
			continue
		}
		var parts []string
		for variant, count := range variants {
			parts = append(parts, fmt.Sprintf("%q (%d)", variant, count))
		}
		sort.Strings(parts)
		issues = append(issues, validationIssue{
			Severity: "warning",
			Field:    field,
			Value:    strings.Join(parts, ", "),
			Message:  "case/format variants found for the same normalized value",
		})
	}

	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Field != issues[j].Field {
			return issues[i].Field < issues[j].Field
		}
		return issues[i].Value < issues[j].Value
	})

	return issues
}

func splitListField(value string) []string {
	var values []string
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '/'
	}) {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func singleValue(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return []string{value}
}

func normalizeValue(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.Join(strings.Fields(value), " ")
	return value
}

func canonicalOutputValue(value string) string {
	value = normalizeValue(value)
	if value == "" {
		return ""
	}
	return value
}

func canonicalOutputList(value string) string {
	parts := splitListField(value)
	if len(parts) == 0 {
		return ""
	}

	seen := make(map[string]bool, len(parts))
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		canonical := canonicalOutputValue(part)
		if canonical == "" || seen[canonical] {
			continue
		}
		seen[canonical] = true
		values = append(values, canonical)
	}
	return strings.Join(values, ", ")
}

func valueSet(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func (issue validationIssue) String() string {
	var location string
	switch {
	case issue.Path != "" && issue.Name != "":
		location = fmt.Sprintf("%s (%s)", issue.Path, issue.Name)
	case issue.Path != "":
		location = issue.Path
	case issue.Name != "":
		location = issue.Name
	default:
		location = "aggregate"
	}

	if issue.Value == "" {
		return fmt.Sprintf("%s: %s: %s", location, issue.Field, issue.Message)
	}
	return fmt.Sprintf("%s: %s=%q: %s", location, issue.Field, issue.Value, issue.Message)
}

// entryToRow converts an AttackEntry to a CSV row
func entryToRow(entry AttackEntry) []string {
	row := make([]string, len(csvHeaders))

	for i, header := range csvHeaders {
		switch header {
		case "name":
			row[i] = entry.Name
		case "title":
			row[i] = entry.Title
		case "repo":
			row[i] = entry.Repo
		case "synopsis":
			row[i] = entry.Synopsis
		case "year":
			if len(entry.StartDate) >= 4 {
				row[i] = entry.StartDate[0:4]
			}
		case "start_date":
			row[i] = entry.StartDate
		case "end_date":
			row[i] = entry.EndDate
		case "attribution_type":
			row[i] = canonicalOutputValue(entry.AttributionType)
		case "component_type":
			row[i] = canonicalOutputValue(entry.ComponentType)
		case "lang":
			row[i] = entry.Lang
		case "cause":
			row[i] = entry.Cause
		case "motive":
			row[i] = entry.Motive
		case "transitive":
			row[i] = strconv.FormatBool(entry.Transitive)
		case "insertion_phase":
			row[i] = canonicalOutputValue(entry.InsertionPhase)
		case "impact_type":
			row[i] = canonicalOutputList(entry.ImpactType)
		case "impact_user_count":
			if entry.ImpactUserCount != 0 {
				row[i] = strconv.Itoa(entry.ImpactUserCount)
			}
		case "references":
			row[i] = strings.Join(entry.References, ", ")
		case "versions":
			row[i] = strings.Join(entry.Versions, ", ")
		case "commits":
			row[i] = strings.Join(entry.Commits, ", ")
		case "historical_artifacts":
			row[i] = strings.Join(entry.HistoricalArtifacts, ", ")
		case "current_artifacts":
			row[i] = strings.Join(entry.CurrentArtifacts, ", ")
		case "domain":
			row[i] = entry.Domain
		case "domain_type":
			row[i] = canonicalOutputValue(entry.DomainType)
		case "artifact_type":
			row[i] = canonicalOutputValue(entry.ArtifactType)
		case "hashes":
			row[i] = strings.Join(entry.Hashes, ", ")
		}
	}

	return row
}
