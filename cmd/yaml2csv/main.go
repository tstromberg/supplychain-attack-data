package main

import (
	"bytes"
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

var attackHeaders = []string{
	"id", "title", "target_name", "target_kind", "target_website", "target_repo",
	"synopsis", "story", "year", "start_date", "end_date", "actor_name", "actor_kind",
	"language", "cause", "motive", "transitive", "phase", "impact_types",
	"impact_users", "references", "campaigns", "artifact_count",
}

var artifactHeaders = []string{
	"attack_id", "attack_title", "campaigns", "artifact_id", "artifact_name",
	"package", "ecosystem", "kind", "website", "repo", "year", "start_date",
	"end_date", "versions", "fixed_versions", "commits", "hashes", "locations",
	"indicators", "evidence", "references", "notes",
}

type Entry struct {
	ID         string      `yaml:"id"`
	Title      string      `yaml:"title"`
	Campaigns  []string    `yaml:"campaigns"`
	Synopsis   string      `yaml:"synopsis"`
	Story      string      `yaml:"story"`
	StartDate  string      `yaml:"start_date"`
	EndDate    string      `yaml:"end_date"`
	Target     Party       `yaml:"target"`
	Actor      Actor       `yaml:"actor"`
	Language   string      `yaml:"language"`
	Method     Method      `yaml:"method"`
	Impact     Impact      `yaml:"impact"`
	Locations  []Location  `yaml:"locations"`
	Indicators []Indicator `yaml:"indicators"`
	Hashes     []string    `yaml:"hashes"`
	Commits    []string    `yaml:"commits"`
	Artifacts  []Artifact  `yaml:"artifacts"`
	References []Reference `yaml:"references"`
	Notes      []string    `yaml:"notes"`
	SourcePath string      `yaml:"-"`
}

type Campaign struct {
	ID         string      `yaml:"id"`
	Title      string      `yaml:"title"`
	Synopsis   string      `yaml:"synopsis"`
	Story      string      `yaml:"story"`
	StartDate  string      `yaml:"start_date"`
	EndDate    string      `yaml:"end_date"`
	Actor      Actor       `yaml:"actor"`
	Impact     Impact      `yaml:"impact"`
	References []Reference `yaml:"references"`
	Notes      []string    `yaml:"notes"`
	SourcePath string      `yaml:"-"`
}

type Party struct {
	Name    string `yaml:"name"`
	Kind    string `yaml:"kind"`
	Website string `yaml:"website"`
	Repo    string `yaml:"repo"`
	Country string `yaml:"country"`
}

type Actor struct {
	Name    string `yaml:"name"`
	Kind    string `yaml:"kind"`
	Country string `yaml:"country"`
}

type Method struct {
	Cause      string `yaml:"cause"`
	Phase      string `yaml:"phase"`
	Motive     string `yaml:"motive"`
	Transitive *bool  `yaml:"transitive"`
}

type Impact struct {
	Types []string `yaml:"types"`
	Users int      `yaml:"users"`
}

type Artifact struct {
	ID            string      `yaml:"id"`
	Name          string      `yaml:"name"`
	Package       string      `yaml:"package"`
	Ecosystem     string      `yaml:"ecosystem"`
	Kind          string      `yaml:"kind"`
	Website       string      `yaml:"website"`
	Repo          string      `yaml:"repo"`
	StartDate     string      `yaml:"start_date"`
	EndDate       string      `yaml:"end_date"`
	Versions      []string    `yaml:"versions"`
	FixedVersions []string    `yaml:"fixed_versions"`
	Locations     []Location  `yaml:"locations"`
	Hashes        []string    `yaml:"hashes"`
	Commits       []string    `yaml:"commits"`
	Indicators    []Indicator `yaml:"indicators"`
	Evidence      []Evidence  `yaml:"evidence"`
	References    []Reference `yaml:"references"`
	Notes         []string    `yaml:"notes"`
}

type Location struct {
	URI  string `yaml:"uri"`
	Role string `yaml:"role"`
}

type Indicator struct {
	Kind  string `yaml:"kind"`
	Value string `yaml:"value"`
}

type Evidence struct {
	Kind string `yaml:"kind"`
	Path string `yaml:"path"`
	Role string `yaml:"role"`
}

type Reference struct {
	URL   string `yaml:"url"`
	Title string `yaml:"title"`
}

type issue struct {
	Severity string
	Field    string
	Value    string
	Path     string
	ID       string
	Message  string
}

var (
	fullDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	hashPattern     = regexp.MustCompile(`^(md5|sha1|sha256|sha384|sha512):([0-9a-fA-F]+)$`)
	partialDate     = regexp.MustCompile(`^\d{4}(-\d{2})?$`)
	versionPattern  = regexp.MustCompile(`^v?[0-9][0-9A-Za-z._+-]*$`)
	versionRange    = regexp.MustCompile(`^v?[0-9][0-9A-Za-z._+-]* - v?[0-9][0-9A-Za-z._+-]*$`)
	compactRange    = regexp.MustCompile(`^v?[0-9][0-9A-Za-z._+]*-v?[0-9][0-9A-Za-z._+]*\.[0-9]`)
	versionLabel    = regexp.MustCompile(`(?i)^(bad|good|clean|safe|malicious|neutralized|affected|vulnerable|fixed):\s*`)
	fileHashKind    = regexp.MustCompile(`^file_(md5|sha1|sha256|sha384|sha512)$`)
	slugPattern     = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	locationRoles   = map[string]bool{"distribution": true, "mirror": true}
)

func main() {
	root := "."
	mode := "attacks"
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--artifacts" {
		mode = "artifacts"
		args = args[1:]
	}
	if len(args) > 0 {
		root = args[0]
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		log.Fatalf("Error: could not determine absolute path for %q: %v", root, err)
	}
	log.Printf("Info: Searching for meta.yaml files in: %s", absRoot)

	var entries []Entry
	var campaigns []Campaign
	campaignIDs := map[string]bool{}

	err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "meta.yaml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if isCampaignPath(absRoot, path) {
			items, err := parseCampaigns(data)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			for i := range items {
				items[i].SourcePath = path
				campaignIDs[items[i].ID] = true
			}
			campaigns = append(campaigns, items...)
			return nil
		}
		items, err := parseEntries(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for i := range items {
			items[i].SourcePath = path
		}
		entries = append(entries, items...)
		return nil
	})
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	validate(entries, campaigns, campaignIDs)
	sort.Slice(entries, func(i, j int) bool {
		return dateLess(entries[i].StartDate, entries[j].StartDate)
	})

	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()
	headers := attackHeaders
	if mode == "artifacts" {
		headers = artifactHeaders
	}
	if err := writer.Write(headers); err != nil {
		log.Fatalf("Error: writing CSV header: %v", err)
	}
	if mode == "artifacts" {
		for _, entry := range entries {
			for _, row := range artifactRows(entry) {
				if err := writer.Write(row); err != nil {
					log.Printf("Warning: writing artifact row: %v", err)
				}
			}
		}
	} else {
		for _, entry := range entries {
			if err := writer.Write(attackRow(entry)); err != nil {
				log.Printf("Warning: writing attack row: %v", err)
			}
		}
	}
	log.Printf("Info: CSV generation complete. Processed %d entries.", len(entries))
}

func parseEntries(data []byte) ([]Entry, error) {
	var entries []Entry
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func parseCampaigns(data []byte) ([]Campaign, error) {
	var campaigns []Campaign
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&campaigns); err != nil {
		return nil, err
	}
	return campaigns, nil
}

func isCampaignPath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	return len(parts) > 0 && parts[0] == "campaigns"
}

func validate(entries []Entry, campaigns []Campaign, campaignIDs map[string]bool) {
	var issues []issue
	seenEntries := map[string]string{}
	for _, entry := range entries {
		issues = append(issues, validateEntry(entry, campaignIDs)...)
		if prev, ok := seenEntries[entry.ID]; ok {
			issues = append(issues, issue{"error", "id", entry.ID, entry.SourcePath, entry.ID, "duplicate id also used in " + prev})
		}
		seenEntries[entry.ID] = entry.SourcePath
	}
	seenCampaigns := map[string]string{}
	for _, campaign := range campaigns {
		issues = append(issues, validateCampaign(campaign)...)
		if prev, ok := seenCampaigns[campaign.ID]; ok {
			issues = append(issues, issue{"error", "id", campaign.ID, campaign.SourcePath, campaign.ID, "duplicate campaign id also used in " + prev})
		}
		seenCampaigns[campaign.ID] = campaign.SourcePath
	}

	errorCount := 0
	for _, item := range issues {
		if item.Severity == "error" {
			errorCount++
		}
		log.Printf("Validation %s: %s", item.Severity, item.String())
	}
	if errorCount > 0 && os.Getenv("YAML2CSV_STRICT") == "1" {
		log.Fatalf("Error: validation failed with %d error(s)", errorCount)
	}
}

func validateEntry(entry Entry, campaignIDs map[string]bool) []issue {
	var issues []issue
	required := map[string]string{
		"id":            entry.ID,
		"title":         entry.Title,
		"synopsis":      entry.Synopsis,
		"start_date":    entry.StartDate,
		"end_date":      entry.EndDate,
		"target.name":   entry.Target.Name,
		"target.kind":   entry.Target.Kind,
		"actor.name":    entry.Actor.Name,
		"actor.kind":    entry.Actor.Kind,
		"method.cause":  entry.Method.Cause,
		"method.phase":  entry.Method.Phase,
		"method.motive": entry.Method.Motive,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, issue{"error", field, "", entry.SourcePath, entry.ID, "required field is empty"})
		}
	}
	if entry.Method.Transitive == nil {
		issues = append(issues, issue{"error", "method.transitive", "", entry.SourcePath, entry.ID, "required field is empty"})
	}
	if !slugPattern.MatchString(entry.ID) {
		issues = append(issues, issue{"error", "id", entry.ID, entry.SourcePath, entry.ID, "use a stable lowercase slug"})
	}
	issues = append(issues, validateTitle(entry.SourcePath, entry.ID, "title", entry.Title)...)
	issues = append(issues, validateSynopsis(entry.SourcePath, entry.ID, "synopsis", entry.Synopsis)...)
	issues = append(issues, validateStory(entry.SourcePath, entry.ID, "story", entry.Story)...)
	issues = append(issues, validateDate(entry.SourcePath, entry.ID, "start_date", entry.StartDate)...)
	issues = append(issues, validateDate(entry.SourcePath, entry.ID, "end_date", entry.EndDate)...)
	issues = append(issues, validateURL(entry.SourcePath, entry.ID, "target.website", entry.Target.Website)...)
	issues = append(issues, validateURL(entry.SourcePath, entry.ID, "target.repo", entry.Target.Repo)...)
	issues = append(issues, validateImpact(entry.SourcePath, entry.ID, "impact", entry.Impact)...)
	issues = append(issues, validateHashes(entry.SourcePath, entry.ID, "hashes", entry.Hashes)...)
	issues = append(issues, validateVersions(entry.SourcePath, entry.ID, "versions", nil)...)
	if len(entry.Campaigns) > 1 {
		issues = append(issues, issue{"error", "campaigns", strings.Join(entry.Campaigns, ","), entry.SourcePath, entry.ID, "attack records must be associated with at most one campaign"})
	}
	for _, campaign := range entry.Campaigns {
		if strings.TrimSpace(campaign) == "" {
			issues = append(issues, issue{"error", "campaigns", "", entry.SourcePath, entry.ID, "campaign id is empty"})
		} else if len(campaignIDs) > 0 && !campaignIDs[campaign] {
			issues = append(issues, issue{"error", "campaigns", campaign, entry.SourcePath, entry.ID, "unknown campaign id"})
		}
	}
	if len(entry.Artifacts) == 0 {
		issues = append(issues, issue{"error", "artifacts", "", entry.SourcePath, entry.ID, "at least one artifact is required"})
	}
	artifactSeen := map[string]bool{}
	for i, artifact := range entry.Artifacts {
		prefix := fmt.Sprintf("artifacts[%d]", i)
		issues = append(issues, validateArtifact(entry, artifact, prefix)...)
		key := artifact.ID
		if key != "" && artifactSeen[key] {
			issues = append(issues, issue{"error", prefix + ".id", key, entry.SourcePath, entry.ID, "duplicate artifact id"})
		}
		artifactSeen[key] = true
	}
	issues = append(issues, validateLocations(entry.SourcePath, entry.ID, "locations", entry.Locations)...)
	issues = append(issues, validateIndicators(entry.SourcePath, entry.ID, "indicators", entry.Indicators)...)
	issues = append(issues, validateReferences(entry.SourcePath, entry.ID, "references", entry.References)...)
	return issues
}

func validateArtifact(entry Entry, artifact Artifact, field string) []issue {
	var issues []issue
	if strings.TrimSpace(artifact.ID) == "" {
		issues = append(issues, issue{"error", field + ".id", "", entry.SourcePath, entry.ID, "required field is empty"})
	} else if !slugPattern.MatchString(artifact.ID) {
		issues = append(issues, issue{"error", field + ".id", artifact.ID, entry.SourcePath, entry.ID, "use a stable lowercase slug"})
	}
	if strings.TrimSpace(artifact.Name) == "" && strings.TrimSpace(artifact.Package) == "" {
		issues = append(issues, issue{"error", field, "", entry.SourcePath, entry.ID, "artifact must set name or package"})
	}
	if strings.TrimSpace(artifact.Kind) == "" {
		issues = append(issues, issue{"error", field + ".kind", "", entry.SourcePath, entry.ID, "required field is empty"})
	}
	issues = append(issues, validateDate(entry.SourcePath, entry.ID, field+".start_date", artifact.StartDate)...)
	issues = append(issues, validateDate(entry.SourcePath, entry.ID, field+".end_date", artifact.EndDate)...)
	issues = append(issues, validateURL(entry.SourcePath, entry.ID, field+".website", artifact.Website)...)
	issues = append(issues, validateURL(entry.SourcePath, entry.ID, field+".repo", artifact.Repo)...)
	issues = append(issues, validateVersions(entry.SourcePath, entry.ID, field+".versions", artifact.Versions)...)
	issues = append(issues, validateVersions(entry.SourcePath, entry.ID, field+".fixed_versions", artifact.FixedVersions)...)
	issues = append(issues, validateHashes(entry.SourcePath, entry.ID, field+".hashes", artifact.Hashes)...)
	issues = append(issues, validateLocations(entry.SourcePath, entry.ID, field+".locations", artifact.Locations)...)
	issues = append(issues, validateIndicators(entry.SourcePath, entry.ID, field+".indicators", artifact.Indicators)...)
	issues = append(issues, validateEvidence(entry.SourcePath, entry.ID, field+".evidence", artifact.Evidence)...)
	issues = append(issues, validateReferences(entry.SourcePath, entry.ID, field+".references", artifact.References)...)
	return issues
}

func validateCampaign(campaign Campaign) []issue {
	var issues []issue
	required := map[string]string{
		"id":         campaign.ID,
		"title":      campaign.Title,
		"synopsis":   campaign.Synopsis,
		"start_date": campaign.StartDate,
		"end_date":   campaign.EndDate,
		"actor.name": campaign.Actor.Name,
		"actor.kind": campaign.Actor.Kind,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, issue{"error", field, "", campaign.SourcePath, campaign.ID, "required campaign field is empty"})
		}
	}
	if !slugPattern.MatchString(campaign.ID) {
		issues = append(issues, issue{"error", "id", campaign.ID, campaign.SourcePath, campaign.ID, "use a stable lowercase slug"})
	}
	issues = append(issues, validateTitle(campaign.SourcePath, campaign.ID, "title", campaign.Title)...)
	issues = append(issues, validateSynopsis(campaign.SourcePath, campaign.ID, "synopsis", campaign.Synopsis)...)
	issues = append(issues, validateStory(campaign.SourcePath, campaign.ID, "story", campaign.Story)...)
	issues = append(issues, validateDate(campaign.SourcePath, campaign.ID, "start_date", campaign.StartDate)...)
	issues = append(issues, validateDate(campaign.SourcePath, campaign.ID, "end_date", campaign.EndDate)...)
	issues = append(issues, validateImpact(campaign.SourcePath, campaign.ID, "impact", campaign.Impact)...)
	issues = append(issues, validateReferences(campaign.SourcePath, campaign.ID, "references", campaign.References)...)
	return issues
}

func validateTitle(path, id, field, value string) []issue {
	var issues []issue
	value = strings.TrimSpace(value)
	chars := len([]rune(value))
	if chars > 90 {
		issues = append(issues, issue{"error", field, strconv.Itoa(chars), path, id, "title must be no more than 90 characters"})
	}
	if strings.HasSuffix(value, ".") || strings.HasSuffix(value, "!") || strings.HasSuffix(value, "?") {
		issues = append(issues, issue{"error", field, value, path, id, "title must not end with sentence punctuation"})
	}
	return issues
}

func validateSynopsis(path, id, field, value string) []issue {
	var issues []issue
	chars := len([]rune(strings.TrimSpace(value)))
	if chars > 280 {
		issues = append(issues, issue{"error", field, strconv.Itoa(chars), path, id, "synopsis must be no more than 280 characters"})
	}
	sentences := countSentences(value)
	if sentences < 1 || sentences > 2 {
		issues = append(issues, issue{"error", field, strconv.Itoa(sentences), path, id, "synopsis must be 1 or 2 sentences"})
	}
	return issues
}

func countSentences(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	count := 0
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '.', '!', '?':
			if value[i] == '.' && i > 0 && i+1 < len(value) && isASCIIDigit(value[i-1]) && isASCIIDigit(value[i+1]) {
				continue
			}
			j := i + 1
			for j < len(value) && (value[j] == '"' || value[j] == '\'' || value[j] == '`' || value[j] == ')' || value[j] == ']') {
				j++
			}
			if j == len(value) {
				count++
				continue
			}
			if value[j] == ' ' || value[j] == '\n' || value[j] == '\t' {
				count++
			}
		}
	}
	return count
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func validateStory(path, id, field, value string) []issue {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	count := len(storyParagraphs(value))
	if count >= 3 && count <= 4 {
		return nil
	}
	return []issue{{"error", field, strconv.Itoa(count), path, id, "story must be 3 to 4 paragraphs separated by blank lines"}}
}

func storyParagraphs(value string) []string {
	blocks := regexp.MustCompile(`\n\s*\n`).Split(strings.TrimSpace(value), -1)
	paragraphs := make([]string, 0, len(blocks))
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block != "" {
			paragraphs = append(paragraphs, block)
		}
	}
	return paragraphs
}

func validateDate(path, id, field, value string) []issue {
	if value == "" || value == "Ongoing" {
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
	return []issue{{"error", field, value, path, id, msg}}
}

func validateURL(path, id, field, value string) []issue {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return nil
	}
	return []issue{{"error", field, value, path, id, "use an http(s) URL"}}
}

func validateImpact(path, id, field string, impact Impact) []issue {
	if len(impact.Types) == 0 {
		return []issue{{"error", field + ".types", "", path, id, "at least one impact type is required"}}
	}
	var issues []issue
	for i, value := range impact.Types {
		if normalize(value) != value {
			issues = append(issues, issue{"error", fmt.Sprintf("%s.types[%d]", field, i), value, path, id, "use lower_snake_case"})
		}
	}
	return issues
}

func validateHashes(path, id, field string, hashes []string) []issue {
	expected := map[string]int{"md5": 32, "sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}
	var issues []issue
	for _, hash := range hashes {
		match := hashPattern.FindStringSubmatch(strings.TrimSpace(hash))
		if len(match) != 3 {
			issues = append(issues, issue{"error", field, hash, path, id, "hash must use md5:, sha1:, sha256:, sha384:, or sha512: followed by hexadecimal digest"})
			continue
		}
		algorithm := strings.ToLower(match[1])
		if len(match[2]) != expected[algorithm] {
			issues = append(issues, issue{"error", field, hash, path, id, fmt.Sprintf("%s digest must be %d hexadecimal characters", algorithm, expected[algorithm])})
		}
	}
	return issues
}

func validateVersions(path, id, field string, versions []string) []issue {
	var issues []issue
	for _, version := range versions {
		value := strings.TrimSpace(version)
		if value == "" {
			issues = append(issues, issue{"error", field, "", path, id, "version value is empty"})
			continue
		}
		if versionLabel.MatchString(value) {
			issues = append(issues, issue{"error", field, value, path, id, "store only the version identifier; use fixed_versions for clean or safe releases"})
			continue
		}
		if strings.ContainsAny(value, "<>=@") {
			issues = append(issues, issue{"error", field, value, path, id, "store only the version identifier, not package names or version constraints"})
			continue
		}
		if versionRange.MatchString(value) {
			continue
		}
		if compactRange.MatchString(value) {
			issues = append(issues, issue{"error", field, value, path, id, "use spaced range syntax, for example 1.2.0 - 1.2.4"})
			continue
		}
		if !versionPattern.MatchString(value) {
			issues = append(issues, issue{"error", field, value, path, id, "use a specific version identifier or a spaced range like 1.2.0 - 1.2.4; move narrative context to notes"})
		}
	}
	return issues
}

func validateLocations(path, id, field string, locations []Location) []issue {
	var issues []issue
	for i, location := range locations {
		prefix := fmt.Sprintf("%s[%d]", field, i)
		if strings.TrimSpace(location.URI) == "" {
			issues = append(issues, issue{"error", prefix + ".uri", "", path, id, "required field is empty"})
		}
		if strings.TrimSpace(location.Role) == "" {
			issues = append(issues, issue{"error", prefix + ".role", "", path, id, "required field is empty"})
		} else if !locationRoles[location.Role] {
			issues = append(issues, issue{"error", prefix + ".role", location.Role, path, id, "use distribution or mirror"})
		}
	}
	return issues
}

func validateIndicators(path, id, field string, indicators []Indicator) []issue {
	var issues []issue
	for i, indicator := range indicators {
		prefix := fmt.Sprintf("%s[%d]", field, i)
		kind := strings.TrimSpace(indicator.Kind)
		value := strings.TrimSpace(indicator.Value)
		if kind == "" || value == "" {
			issues = append(issues, issue{"error", prefix, "", path, id, "indicator must set kind and value"})
			continue
		}
		if normalize(kind) != kind {
			issues = append(issues, issue{"error", prefix + ".kind", kind, path, id, "use lower_snake_case"})
		}
		if match := fileHashKind.FindStringSubmatch(kind); len(match) == 2 {
			parts := strings.Fields(value)
			if len(parts) < 2 {
				issues = append(issues, issue{"error", prefix + ".value", value, path, id, "file hash indicators must use '<file> <digest>'"})
				continue
			}
			algorithm := match[1]
			hash := parts[len(parts)-1]
			if !hashMatchesAlgorithm(algorithm, hash) {
				issues = append(issues, issue{"error", prefix + ".value", value, path, id, fmt.Sprintf("file_%s must end with a valid %s digest", algorithm, algorithm)})
			}
		}
	}
	return issues
}

func hashMatchesAlgorithm(algorithm, digest string) bool {
	expected := map[string]int{"md5": 32, "sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}
	if len(digest) != expected[algorithm] {
		return false
	}
	for _, char := range digest {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func validateEvidence(metaPath, id, field string, evidence []Evidence) []issue {
	var issues []issue
	for i, item := range evidence {
		prefix := fmt.Sprintf("%s[%d]", field, i)
		if strings.TrimSpace(item.Kind) == "" || strings.TrimSpace(item.Path) == "" {
			issues = append(issues, issue{"error", prefix, "", metaPath, id, "evidence must set kind and path"})
			continue
		}
		cleanPath := filepath.Clean(strings.TrimSpace(item.Path))
		if filepath.IsAbs(cleanPath) || strings.Contains(cleanPath, "://") {
			issues = append(issues, issue{"error", prefix + ".path", item.Path, metaPath, id, "evidence path must be a local relative path; use locations or references for URLs"})
			continue
		}
		if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
			issues = append(issues, issue{"error", prefix + ".path", item.Path, metaPath, id, "evidence path must stay inside the attack directory"})
			continue
		}
		fullPath := filepath.Join(filepath.Dir(metaPath), cleanPath)
		if _, err := os.Stat(fullPath); err != nil {
			issues = append(issues, issue{"error", prefix + ".path", item.Path, metaPath, id, "evidence path does not exist"})
		}
	}
	return issues
}

func validateReferences(path, id, field string, refs []Reference) []issue {
	var issues []issue
	for i, ref := range refs {
		if strings.TrimSpace(ref.URL) == "" {
			issues = append(issues, issue{"error", fmt.Sprintf("%s[%d].url", field, i), "", path, id, "required field is empty"})
		}
	}
	return issues
}

func attackRow(entry Entry) []string {
	transitive := ""
	if entry.Method.Transitive != nil {
		transitive = strconv.FormatBool(*entry.Method.Transitive)
	}
	return []string{
		entry.ID,
		entry.Title,
		entry.Target.Name,
		entry.Target.Kind,
		entry.Target.Website,
		entry.Target.Repo,
		entry.Synopsis,
		entry.Story,
		year(entry.StartDate),
		entry.StartDate,
		entry.EndDate,
		entry.Actor.Name,
		entry.Actor.Kind,
		entry.Language,
		entry.Method.Cause,
		entry.Method.Motive,
		transitive,
		entry.Method.Phase,
		strings.Join(entry.Impact.Types, ", "),
		intString(entry.Impact.Users),
		joinRefs(entry.References),
		strings.Join(entry.Campaigns, ", "),
		intString(len(entry.Artifacts)),
	}
}

func artifactRows(entry Entry) [][]string {
	rows := make([][]string, 0, len(entry.Artifacts))
	for _, artifact := range entry.Artifacts {
		start := firstNonEmpty(artifact.StartDate, entry.StartDate)
		end := firstNonEmpty(artifact.EndDate, entry.EndDate)
		refs := artifact.References
		if len(refs) == 0 {
			refs = entry.References
		}
		rows = append(rows, []string{
			entry.ID,
			entry.Title,
			strings.Join(entry.Campaigns, ", "),
			artifact.ID,
			firstNonEmpty(artifact.Name, artifact.Package),
			artifact.Package,
			artifact.Ecosystem,
			artifact.Kind,
			artifact.Website,
			artifact.Repo,
			year(start),
			start,
			end,
			strings.Join(artifact.Versions, ", "),
			strings.Join(artifact.FixedVersions, ", "),
			strings.Join(append(entry.Commits, artifact.Commits...), ", "),
			strings.Join(append(entry.Hashes, artifact.Hashes...), ", "),
			joinLocations(append(entry.Locations, artifact.Locations...)),
			joinIndicators(append(entry.Indicators, artifact.Indicators...)),
			joinEvidence(artifact.Evidence),
			joinRefs(refs),
			strings.Join(artifact.Notes, " "),
		})
	}
	return rows
}

func dateLess(a, b string) bool {
	if a == "" {
		return false
	}
	if b == "" {
		return true
	}
	da, ea := time.Parse("2006-01-02", a)
	db, eb := time.Parse("2006-01-02", b)
	if ea == nil && eb == nil {
		return da.Before(db)
	}
	return a < b
}

func year(date string) string {
	if len(date) >= 4 {
		return date[:4]
	}
	return ""
}

func intString(value int) string {
	if value == 0 {
		return ""
	}
	return strconv.Itoa(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func joinRefs(refs []Reference) string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		if strings.TrimSpace(ref.Title) != "" {
			values = append(values, ref.Title+" <"+ref.URL+">")
		} else {
			values = append(values, ref.URL)
		}
	}
	return strings.Join(values, ", ")
}

func joinLocations(locations []Location) string {
	values := make([]string, 0, len(locations))
	for _, location := range locations {
		values = append(values, location.Role+":"+location.URI)
	}
	return strings.Join(values, ", ")
}

func joinIndicators(indicators []Indicator) string {
	values := make([]string, 0, len(indicators))
	for _, indicator := range indicators {
		values = append(values, indicator.Kind+":"+indicator.Value)
	}
	return strings.Join(values, ", ")
}

func joinEvidence(evidence []Evidence) string {
	values := make([]string, 0, len(evidence))
	for _, item := range evidence {
		values = append(values, item.Path)
	}
	return strings.Join(values, ", ")
}

func normalize(value string) string {
	return strings.Trim(strings.ToLower(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(value, "_")), "_")
}

func (item issue) String() string {
	location := item.Path
	if item.ID != "" {
		location = fmt.Sprintf("%s (%s)", item.Path, item.ID)
	}
	if item.Value == "" {
		return fmt.Sprintf("%s: %s: %s", location, item.Field, item.Message)
	}
	return fmt.Sprintf("%s: %s=%q: %s", location, item.Field, item.Value, item.Message)
}
