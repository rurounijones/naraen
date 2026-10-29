package storage

import (
	"strings"
	"testing"

	"github.com/rurounijones/naraen/internal/oid"
)

func TestObjectKey(t *testing.T) {
	id, err := oid.Parse("ab" + "cd" + strings.Repeat("0", 60))
	if err != nil {
		t.Fatal(err)
	}
	want := "42/ab/cd/abcd" + strings.Repeat("0", 60)
	if got := ObjectKey("42", id); got != want {
		t.Errorf("ObjectKey = %q, want %q", got, want)
	}
}
