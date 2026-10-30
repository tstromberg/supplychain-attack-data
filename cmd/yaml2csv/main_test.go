package main

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestUnknownIncidentFactsMayBeOmitted(t *testing.T) {
	entry := Entry{
		ID: "example", Title: "Example release distributed a credential stealer",
		Synopsis:   "The official release contained a credential stealer.",
		Story:      "The official release contained a credential stealer.\n\nThe maintainer removed it.",
		PullQuote:  &PullQuote{Text: "The maintainer removed it.", After: 2},
		Target:     Party{Name: "Example", Kind: "library"},
		Method:     Method{Phase: "distribution"},
		Impact:     Impact{Types: []string{"credential_theft"}},
		Artifacts:  []Artifact{{ID: "example", Name: "Example", Kind: "source_archive"}},
		References: []Reference{{URL: "https://example.org/advisory", Title: "Advisory"}},
	}
	if got := validateEntry(entry, nil); len(got) != 0 {
		t.Fatalf("unknown facts should be omitted, got: %+v", got)
	}
	entry.StartDate = "2026-13-40"
	if got := validateEntry(entry, nil); len(got) == 0 {
		t.Fatal("a supplied invalid date must still fail validation")
	}
	entry.StartDate = ""
	entry.Target.Name = ""
	if got := validateEntry(entry, nil); len(got) == 0 {
		t.Fatal("the attacked entity must still be identified")
	}
}

func TestRequiredStoryParagraphs(t *testing.T) {
	for _, tt := range []struct {
		name, story string
		valid       bool
	}{
		{"missing", "", false},
		{"whitespace only", " \n\n\t ", false},
		{"one paragraph", "One paragraph.", false},
		{"wrapped paragraph", "One paragraph\ncontinues here.", false},
		{"two paragraphs", "First.\n\nSecond.", true},
		{"four paragraphs", "First.\n\nSecond.\n\nThird.\n\nFourth.", true},
		{"five paragraphs", "First.\n\nSecond.\n\nThird.\n\nFourth.\n\nFifth.", false},
		{"blank lines with whitespace", "First.\n \t\nSecond.", true},
		{"CRLF paragraphs", "First.\r\n\r\nSecond.", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := validateStory("meta.yaml", "example", "story", tt.story)
			if (len(got) == 0) != tt.valid {
				t.Fatalf("valid = %v, want %v; issues: %+v", len(got) == 0, tt.valid, got)
			}
		})
	}
}

func TestRequiredPullQuote(t *testing.T) {
	story := "First paragraph.\n \t\nSecond paragraph."
	for _, tt := range []struct {
		name  string
		quote *PullQuote
		valid bool
	}{
		{"missing", nil, false},
		{"empty object", &PullQuote{}, false},
		{"blank text", &PullQuote{Text: " \n\t", After: 1}, false},
		{"visible after first", &PullQuote{Text: "First paragraph.", After: 1}, true},
		{"visible after last", &PullQuote{Text: "Second paragraph.", After: 2}, true},
		{"zero is never rendered", &PullQuote{Text: "First paragraph.", After: 0}, false},
		{"negative position", &PullQuote{Text: "First paragraph.", After: -1}, false},
		{"past story", &PullQuote{Text: "First paragraph.", After: 3}, false},
		{"too many words", &PullQuote{Text: strings.Repeat("word ", 41), After: 1}, false},
		{"too many sentences", &PullQuote{Text: "One. Two. Three.", After: 1}, false},
		{"long caption", &PullQuote{Text: "First paragraph.", Caption: strings.Repeat("word ", 9), After: 1}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := validatePullQuote("meta.yaml", "example", "pull_quote", tt.quote, story)
			if (len(got) == 0) != tt.valid {
				t.Fatalf("valid = %v, want %v; issues: %+v", len(got) == 0, tt.valid, got)
			}
		})
	}
}

func TestArticleRequirementsApplyToAttacksAndCampaigns(t *testing.T) {
	for name, issues := range map[string][]issue{
		"attack":   validateEntry(Entry{ID: "example"}, nil),
		"campaign": validateCampaign(Campaign{ID: "example"}),
	} {
		for _, field := range []string{"story", "pull_quote"} {
			found := false
			for _, item := range issues {
				if item.Field == field && item.Severity == "error" {
					found = true
				}
			}
			if !found {
				t.Errorf("%s missing %s should be a validation error", name, field)
			}
		}
	}
}

func TestComposerDevelopmentVersions(t *testing.T) {
	for _, version := range []string{"dev-main", "dev-nova4support", "dev-using-inertia", "dev-nova5"} {
		if got := validateVersions("meta.yaml", "example", "versions", []string{version}); len(got) != 0 {
			t.Errorf("valid Composer identifier %q: %+v", version, got)
		}
	}
	for _, version := range []string{"dev-", "dev-main was compromised", "package@dev-main", ">=dev-main"} {
		if got := validateVersions("meta.yaml", "example", "versions", []string{version}); len(got) == 0 {
			t.Errorf("invalid identifier %q passed validation", version)
		}
	}
}

func TestHashListUnmarshalYAML(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want HashList
	}{
		{
			name: "string entries",
			in:   "hashes:\n- sha256:abcdef\n",
			want: HashList{{Digest: "sha256:abcdef"}},
		},
		{
			name: "map entries",
			in:   "hashes:\n- sha256: abcdef\n",
			want: HashList{{Digest: "sha256:abcdef"}},
		},
		{
			name: "single scalar",
			in:   "hashes: sha256:abcdef\n",
			want: HashList{{Digest: "sha256:abcdef"}},
		},
		{
			name: "subject and role",
			in:   "hashes:\n- sha256: abcdef\n  of: file\n  path: dist/index.js\n  role: malicious\n",
			want: HashList{{Digest: "sha256:abcdef", Of: "file", Path: "dist/index.js", Role: "malicious"}},
		},
		{
			name: "clean baseline",
			in:   "hashes:\n- md5: abcdef\n  of: archive\n  role: clean\n  note: upstream release\n",
			want: HashList{{Digest: "md5:abcdef", Of: "archive", Role: "clean", Note: "upstream release"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got struct {
				Hashes HashList `yaml:"hashes"`
			}
			if err := yaml.Unmarshal([]byte(tt.in), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Hashes, tt.want) {
				t.Fatalf("hashes = %#v, want %#v", got.Hashes, tt.want)
			}
		})
	}
}

func TestValidateNotes(t *testing.T) {
	tests := []struct {
		name  string
		notes []string
		want  int
	}{
		{"empty", nil, 0},
		{"within limits", []string{"short", strings.Repeat("a", noteMaxChars)}, 0},
		{"too many", make([]string, notesMax+1), 1},
		{"one too long", []string{strings.Repeat("a", noteMaxChars+1)}, 1},
		{"both", []string{
			strings.Repeat("a", noteMaxChars+1),
			strings.Repeat("b", noteMaxChars+1),
			"", "", "",
		}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(validateNotes("meta.yaml", "example", "notes", tt.notes)); got != tt.want {
				t.Errorf("validateNotes(%d notes) = %d issues, want %d", len(tt.notes), got, tt.want)
			}
		})
	}
}

func TestValidateDistinctIncidents(t *testing.T) {
	entry := func(id, target, start, end, path string) Entry {
		return Entry{ID: id, Target: Party{Name: target}, StartDate: start, EndDate: end, SourcePath: path}
	}
	tests := []struct {
		name     string
		entries  []Entry
		want     int
		severity string
	}{
		{
			name: "same incident under a different id",
			entries: []Entry{
				entry("linux", "linux", "2003-11-04", "2003-11-05", "oss/attacks/linux/meta.yaml"),
				entry("linux-kernel-cvs", "Linux kernel", "2003-11-05", "2003-11-06", "oss/attacks/linux-kernel-cvs/meta.yaml"),
			},
			want:     1,
			severity: "warning",
		},
		{
			name: "qualified target name still matches",
			entries: []Entry{
				entry("php", "php", "2021-03-28", "2021-03-28", "oss/attacks/php/2021/meta.yaml"),
				entry("php-src-git", "php-src", "2021-03-28", "2021-03-29", "oss/attacks/php-src-git/meta.yaml"),
			},
			want:     1,
			severity: "warning",
		},
		{
			name: "record dropped beside dated subdirectories",
			entries: []Entry{
				entry("transmission-2016-03", "transmission", "2016-03-04", "2016-03-06", "oss/attacks/transmission/2016-03/meta.yaml"),
				entry("transmission-2016-08", "transmission", "2016-08-28", "2016-08-30", "oss/attacks/transmission/2016-08/meta.yaml"),
				entry("transmission-keranger", "Transmission", "2016-03-04", "2016-03-05", "oss/attacks/transmission/meta.yaml"),
			},
			want:     1,
			severity: "error",
		},
		{
			name: "same target attacked again later is not a duplicate",
			entries: []Entry{
				entry("ammyy-2015", "Ammyy Admin", "2015-10-01", "2015-10-30", "oss/attacks/ammyy-admin-2015/meta.yaml"),
				entry("ammyy-2016", "Ammyy Admin", "2016-06-01", "2016-06-30", "oss/attacks/ammyy-admin-2016/meta.yaml"),
			},
			want: 0,
		},
		{
			name: "unrelated targets in the same window",
			entries: []Entry{
				entry("a", "eslint-scope", "2018-07-12", "2018-07-12", "oss/attacks/a/meta.yaml"),
				entry("b", "conventional-changelog", "2018-07-12", "2018-07-12", "oss/attacks/b/meta.yaml"),
			},
			want: 0,
		},
		{
			name: "missing target name is not compared",
			entries: []Entry{
				entry("a", "", "2020-01-01", "2020-01-02", "oss/attacks/a/meta.yaml"),
				entry("b", "", "2020-01-01", "2020-01-02", "oss/attacks/b/meta.yaml"),
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateDistinctIncidents(tt.entries)
			if len(got) != tt.want {
				t.Fatalf("validateDistinctIncidents() = %d issue(s), want %d: %v", len(got), tt.want, got)
			}
			if tt.want > 0 && got[0].Severity != tt.severity {
				t.Errorf("severity = %q, want %q", got[0].Severity, tt.severity)
			}
		})
	}
}
