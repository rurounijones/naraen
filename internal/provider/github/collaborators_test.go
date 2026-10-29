package github

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rurounijones/naraen/internal/datastore"
)

var update = flag.Bool("update", false, "rewrite golden files")

// golden parses testdata/<name>.json with parse and compares the result with
// testdata/<name>.golden.json.
func golden[T any](t *testing.T, name string, parse func(io.Reader) (T, error)) {
	t.Helper()
	in, err := os.Open(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	got, err := parse(in)
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", name+".golden.json")
	if *update {
		if err := os.WriteFile(path, append(gotJSON, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != string(gotJSON) {
		t.Errorf("golden mismatch.\n got: %s\nwant: %s", gotJSON, want)
	}
}

func TestParseCollaboratorsGolden(t *testing.T) {
	golden(t, "collaborators", func(r io.Reader) ([]datastore.Grant, error) { return ParseCollaborators("42", r) })
}

func TestParseMembersGolden(t *testing.T) {
	golden(t, "members", ParseMembers)
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string]string{
		"not json":      `nope`,
		"not an array":  `{}`,
		"missing id":    `[{"login":"a","permissions":{"pull":true}}]`,
		"missing login": `[{"id":1,"permissions":{"pull":true}}]`,
	} {
		if _, err := ParseCollaborators("1", strings.NewReader(in)); err == nil {
			t.Errorf("collaborators %s: expected error", name)
		}
		if _, err := ParseMembers(strings.NewReader(in)); err == nil {
			t.Errorf("members %s: expected error", name)
		}
	}
}

// The members and collaborators fixtures overlap except for the outside
// collaborator (id 7), whose grant must be dropped.
func TestMemberGrantsDropsOutsideCollaborators(t *testing.T) {
	open := func(name string) *os.File {
		f, err := os.Open(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	members, err := ParseMembers(open("members.json"))
	if err != nil {
		t.Fatal(err)
	}
	grants, err := ParseCollaborators("42", open("collaborators.json"))
	if err != nil {
		t.Fatal(err)
	}
	kept := MemberGrants(members, grants)
	if len(kept) != len(grants)-1 {
		t.Fatalf("kept %d of %d grants", len(kept), len(grants))
	}
	for _, g := range kept {
		if g.IdentityID == PersonID(7) {
			t.Fatal("outside collaborator kept a grant")
		}
	}
	// The result is a valid snapshot.
	if _, err := datastore.NewSnapshot(datastore.Data{
		Identities: members,
		Repos:      []datastore.Repo{{ID: "42", Path: "acme/assets"}},
		Grants:     kept,
	}); err != nil {
		t.Fatalf("snapshot from members and grants: %v", err)
	}
	if got := MemberGrants(nil, grants); !reflect.DeepEqual(got, []datastore.Grant{}) {
		t.Fatalf("no members kept %v", got)
	}
}
