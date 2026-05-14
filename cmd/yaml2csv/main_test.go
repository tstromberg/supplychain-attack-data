package main

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHashListUnmarshalYAML(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want HashList
	}{
		{
			name: "string entries",
			in:   "hashes:\n- sha256:abcdef\n",
			want: HashList{"sha256:abcdef"},
		},
		{
			name: "map entries",
			in:   "hashes:\n- sha256: abcdef\n",
			want: HashList{"sha256:abcdef"},
		},
		{
			name: "single scalar",
			in:   "hashes: sha256:abcdef\n",
			want: HashList{"sha256:abcdef"},
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
