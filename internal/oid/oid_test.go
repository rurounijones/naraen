package oid

import (
	"errors"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	good := strings.Repeat("a1", 32)
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"valid", good, true},
		{"all digits", strings.Repeat("0", 64), true},
		{"all nines", strings.Repeat("9", 64), true},
		{"all a", strings.Repeat("a", 64), true},
		{"all f", strings.Repeat("f", 64), true},
		{"empty", "", false},
		{"too short", good[:63], false},
		{"too long", good + "a", false},
		{"uppercase", strings.ToUpper(good), false},
		{"non hex", strings.Repeat("g", 64), false},
		{"slash", good[:62] + "/a", false},
		{"dot dot", good[:60] + "../a", false},
		{"trailing newline", good[:63] + "\n", false},
		{"nul", good[:63] + "\x00", false},
		{"first char below range", "/" + good[1:], false},
		{"first char above digits", ":" + good[1:], false},
		{"first char below a", "`" + good[1:], false},
		{"first char above f", "g" + good[1:], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Valid(tt.in); got != tt.want {
				t.Errorf("Valid(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	good := strings.Repeat("ab", 32)
	got, err := Parse(good)
	if err != nil || string(got) != good {
		t.Fatalf("Parse(good) = %q, %v", got, err)
	}
	if _, err := Parse("nope"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Parse(nope) error = %v, want ErrInvalid", err)
	}
}

func FuzzValid(f *testing.F) {
	f.Add(strings.Repeat("a", 64))
	f.Add("")
	f.Add("../../etc/passwd")
	f.Fuzz(func(t *testing.T, s string) {
		if Valid(s) {
			if len(s) != Length || strings.ContainsAny(s, "/.\\ \x00\n") || s != strings.ToLower(s) {
				t.Fatalf("Valid accepted %q", s)
			}
		}
	})
}
