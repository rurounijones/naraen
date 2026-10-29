package pathnorm

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"acme/assets", "acme/assets", false},
		{"/acme/assets", "acme/assets", false},
		{"acme/assets.git", "acme/assets", false},
		{"/Acme/Assets.git", "acme/assets", false},
		{"acme/assets.GIT", "acme/assets", false},
		{"az09/-_.x", "az09/-_.x", false}, // every accepted character class and its edges
		{"/" + strings.Repeat("a", 99) + "/" + strings.Repeat("b", 99), strings.Repeat("a", 99) + "/" + strings.Repeat("b", 99), false}, // exactly MaxLength
		{"`/b", "", true},
		{"{/b", "", true},
		{"//b", "", true},
		{":/b", "", true},
		{"@/b", "", true},
		{"a/,", "", true},
		{"a/*", "", true},
		{"a/^", "", true},
		{"a/.-", "a/.-", false},
		{"0/.Git", "", true}, // fuzz regression: must not normalize to 0/.git
		{"acme/my.repo-name_1", "acme/my.repo-name_1", false},
		{"", "", true},
		{"/", "", true},
		{"acme", "", true},
		{"acme/", "", true},
		{"/acme", "", true},
		{"acme/assets/extra", "", true},
		{"//acme/assets", "", true},
		{"acme//assets", "", true},
		{"../assets", "", true},
		{"acme/..", "", true},
		{"./assets", "", true},
		{"acme/.", "", true},
		{"acme/%2e%2e", "", true},
		{"acme%2fassets", "", true},
		{"acme%2Fassets", "", true},
		{`acme\assets`, "", true},
		{"acme/assets\x00", "", true},
		{"acme/assets\n", "", true},
		{"acme/ass ets", "", true},
		{"acme/assets.git.git", "", true},
		{"acme/ässets", "", true},
		{"acme.git/assets", "", true},
		{strings.Repeat("a", MaxLength) + "/b", "", true},
	}
	for _, tt := range tests {
		got, err := Normalize(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("Normalize(%q) = %q, %v; want %q, err=%v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"acme/assets", "/a/b.git", "../x", "a%2fb", "a/b/c", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := Normalize(s)
		if err != nil {
			return
		}
		if got != strings.ToLower(got) || strings.Count(got, "/") != 1 ||
			strings.ContainsAny(got, "\\%\x00\n") || strings.HasSuffix(got, ".git") {
			t.Fatalf("Normalize(%q) = %q", s, got)
		}
		again, err := Normalize(got)
		if err != nil || again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q, %v", s, got, again, err)
		}
	})
}
