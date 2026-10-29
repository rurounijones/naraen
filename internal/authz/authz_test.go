package authz

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/lfs"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func fp(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func newStore(t *testing.T) *datastore.Store {
	t.Helper()
	person := func(id string, active bool) datastore.Identity {
		return datastore.Identity{ID: id, Kind: datastore.KindPerson, Active: active}
	}
	snap, err := datastore.NewSnapshot(datastore.Data{
		Identities: []datastore.Identity{
			person("reader", true),
			person("writer", true),
			person("nogrant", true),
			person("disabled", false),
		},
		Keys: []datastore.Key{
			{Fingerprint: fp("reader"), IdentityID: "reader"},
			{Fingerprint: fp("disabled"), IdentityID: "disabled"},
		},
		Repos: []datastore.Repo{
			{ID: "r1", Path: "acme/assets", Aliases: []string{"acme/old"}},
			{ID: "r2", Path: "acme/other"},
		},
		Grants: []datastore.Grant{
			{IdentityID: "reader", RepoID: "r1", Level: datastore.LevelRead},
			{IdentityID: "writer", RepoID: "r1", Level: datastore.LevelWrite},
			{IdentityID: "disabled", RepoID: "r1", Level: datastore.LevelAdmin},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	st := datastore.NewStore(time.Hour, datastore.DefaultLimits)
	st.Now = func() time.Time { return now }
	if err := st.Swap(st.StartSync(), snap); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestAuthorizeMatrix(t *testing.T) {
	a := New(newStore(t))
	tests := []struct {
		name     string
		identity string
		path     string
		op       lfs.Operation
		want     string // repo ID, "" means denied
	}{
		{"reader downloads", "reader", "acme/assets", lfs.Download, "r1"},
		{"reader cannot upload", "reader", "acme/assets", lfs.Upload, ""},
		{"writer downloads", "writer", "acme/assets", lfs.Download, "r1"},
		{"writer uploads", "writer", "/Acme/Assets.git", lfs.Upload, "r1"},
		{"alias resolves", "reader", "acme/old", lfs.Download, "r1"},
		{"no grant on repo", "reader", "acme/other", lfs.Download, ""},
		{"identity without grants", "nogrant", "acme/assets", lfs.Download, ""},
		{"inactive identity", "disabled", "acme/assets", lfs.Download, ""},
		{"unknown identity", "ghost", "acme/assets", lfs.Download, ""},
		{"unknown repo", "reader", "acme/nope", lfs.Download, ""},
		{"traversal path", "reader", "acme/../assets", lfs.Download, ""},
		{"encoded slash", "reader", "acme%2fassets", lfs.Download, ""},
		{"unknown operation", "writer", "acme/assets", lfs.Operation("delete"), ""},
		{"empty operation", "writer", "acme/assets", lfs.Operation(""), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := a.Authorize(tt.identity, tt.path, tt.op)
			if tt.want == "" {
				if !errors.Is(err, ErrDenied) || got != "" {
					t.Fatalf("got %q, %v; want denial", got, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestRecheck(t *testing.T) {
	st := newStore(t)
	a := New(st)
	if err := a.Recheck("writer", "r1", lfs.Upload); err != nil {
		t.Fatalf("writer upload: %v", err)
	}
	for name, c := range map[string]struct {
		id, repo string
		op       lfs.Operation
	}{
		"insufficient level": {"reader", "r1", lfs.Upload},
		"no grant":           {"reader", "r2", lfs.Download},
		"unknown repo":       {"writer", "r9", lfs.Download},
		"inactive":           {"disabled", "r1", lfs.Download},
		"unknown identity":   {"ghost", "r1", lfs.Download},
		"unknown operation":  {"writer", "r1", lfs.Operation("delete")},
	} {
		if err := a.Recheck(c.id, c.repo, c.op); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A revocation after the token was minted takes effect on the next request.
	st.Narrow(datastore.Narrowing{DropGrants: []datastore.GrantRef{{IdentityID: "writer", RepoID: "r1"}}})
	if err := a.Recheck("writer", "r1", lfs.Download); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked grant still passes: %v", err)
	}
}

func TestIdentityForKey(t *testing.T) {
	a := New(newStore(t))
	if id, err := a.IdentityForKey(fp("reader")); err != nil || id.ID != "reader" {
		t.Fatalf("known key: %v, %v", id, err)
	}
	for _, f := range []string{fp("disabled"), fp("unknown"), ""} {
		if _, err := a.IdentityForKey(f); !errors.Is(err, ErrDenied) {
			t.Errorf("IdentityForKey(%q) = %v, want ErrDenied", f, err)
		}
	}
}

func TestFailsClosedWithoutFreshSnapshot(t *testing.T) {
	empty := New(datastore.NewStore(time.Hour, datastore.DefaultLimits))
	if _, err := empty.IdentityForKey(fp("reader")); !errors.Is(err, ErrDenied) {
		t.Errorf("not ready: IdentityForKey = %v", err)
	}
	if _, err := empty.Authorize("reader", "acme/assets", lfs.Download); !errors.Is(err, ErrDenied) {
		t.Errorf("not ready: Authorize = %v", err)
	}
	if err := empty.Recheck("reader", "r1", lfs.Download); !errors.Is(err, ErrDenied) {
		t.Errorf("not ready: Recheck = %v", err)
	}

	st := newStore(t)
	st.Now = func() time.Time { return now.Add(2 * time.Hour) }
	stale := New(st)
	if _, err := stale.IdentityForKey(fp("reader")); !errors.Is(err, ErrDenied) {
		t.Errorf("stale: IdentityForKey = %v", err)
	}
	if _, err := stale.Authorize("reader", "acme/assets", lfs.Download); !errors.Is(err, ErrDenied) {
		t.Errorf("stale: Authorize = %v", err)
	}
	if err := stale.Recheck("reader", "r1", lfs.Download); !errors.Is(err, ErrDenied) {
		t.Errorf("stale: Recheck = %v", err)
	}
}
