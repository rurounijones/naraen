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

// checkDenial asserts that err is a denial for exactly the given reason, and
// that its message carries no hint of that reason.
func checkDenial(t *testing.T, err error, want Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("allowed, want denial for %q", want)
	}
	if !errors.Is(err, ErrDenied) || ReasonOf(err) != want {
		t.Fatalf("err = %v (reason %q), want denial for %q", err, ReasonOf(err), want)
	}
	if err.Error() != ErrDenied.Error() {
		t.Fatalf("message %q reveals more than ErrDenied", err.Error())
	}
}

func TestAuthorizeMatrix(t *testing.T) {
	a := New(newStore(t))
	tests := []struct {
		name     string
		identity string
		path     string
		op       lfs.Operation
		want     string // repo ID, "" means denied for reason
		reason   Reason
	}{
		{"reader downloads", "reader", "acme/assets", lfs.Download, "r1", ""},
		{"reader cannot upload", "reader", "acme/assets", lfs.Upload, "", ReasonInsufficientGrant},
		{"writer downloads", "writer", "acme/assets", lfs.Download, "r1", ""},
		{"writer uploads", "writer", "/Acme/Assets.git", lfs.Upload, "r1", ""},
		{"alias resolves", "reader", "acme/old", lfs.Download, "r1", ""},
		{"no grant on repo", "reader", "acme/other", lfs.Download, "", ReasonInsufficientGrant},
		{"identity without grants", "nogrant", "acme/assets", lfs.Download, "", ReasonInsufficientGrant},
		{"inactive identity", "disabled", "acme/assets", lfs.Download, "", ReasonInactiveIdentity},
		{"unknown identity", "ghost", "acme/assets", lfs.Download, "", ReasonUnknownIdentity},
		{"unknown repo", "reader", "acme/nope", lfs.Download, "", ReasonUnknownRepo},
		{"traversal path", "reader", "acme/../assets", lfs.Download, "", ReasonBadPath},
		{"encoded slash", "reader", "acme%2fassets", lfs.Download, "", ReasonBadPath},
		{"unknown operation", "writer", "acme/assets", lfs.Operation("delete"), "", ReasonBadOperation},
		{"empty operation", "writer", "acme/assets", lfs.Operation(""), "", ReasonBadOperation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := a.Authorize(tt.identity, tt.path, tt.op)
			if tt.want == "" {
				checkDenial(t, err, tt.reason)
				if got != "" {
					t.Fatalf("denied but returned repo %q", got)
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
		reason   Reason
	}{
		"insufficient level": {"reader", "r1", lfs.Upload, ReasonInsufficientGrant},
		"no grant":           {"reader", "r2", lfs.Download, ReasonInsufficientGrant},
		"unknown repo":       {"writer", "r9", lfs.Download, ReasonInsufficientGrant},
		"inactive":           {"disabled", "r1", lfs.Download, ReasonInactiveIdentity},
		"unknown identity":   {"ghost", "r1", lfs.Download, ReasonUnknownIdentity},
		"unknown operation":  {"writer", "r1", lfs.Operation("delete"), ReasonBadOperation},
	} {
		t.Run(name, func(t *testing.T) {
			checkDenial(t, a.Recheck(c.id, c.repo, c.op), c.reason)
		})
	}
	// A revocation after the token was minted takes effect on the next request.
	st.Narrow(datastore.Narrowing{DropGrants: []datastore.GrantRef{{IdentityID: "writer", RepoID: "r1"}}})
	checkDenial(t, a.Recheck("writer", "r1", lfs.Download), ReasonInsufficientGrant)
}

func TestIdentityForKey(t *testing.T) {
	a := New(newStore(t))
	if id, err := a.IdentityForKey(fp("reader")); err != nil || id.ID != "reader" {
		t.Fatalf("known key: %v, %v", id, err)
	}
	for f, reason := range map[string]Reason{
		fp("disabled"): ReasonInactiveIdentity,
		fp("unknown"):  ReasonUnknownKey,
		"":             ReasonUnknownKey,
	} {
		_, err := a.IdentityForKey(f)
		checkDenial(t, err, reason)
	}
}

func TestFailsClosedWithoutFreshSnapshot(t *testing.T) {
	empty := New(datastore.NewStore(time.Hour, datastore.DefaultLimits))
	_, err := empty.IdentityForKey(fp("reader"))
	checkDenial(t, err, ReasonNotReady)
	_, err = empty.Authorize("reader", "acme/assets", lfs.Download)
	checkDenial(t, err, ReasonNotReady)
	checkDenial(t, empty.Recheck("reader", "r1", lfs.Download), ReasonNotReady)

	st := newStore(t)
	st.Now = func() time.Time { return now.Add(2 * time.Hour) }
	stale := New(st)
	_, err = stale.IdentityForKey(fp("reader"))
	checkDenial(t, err, ReasonStale)
	_, err = stale.Authorize("reader", "acme/assets", lfs.Download)
	checkDenial(t, err, ReasonStale)
	checkDenial(t, stale.Recheck("reader", "r1", lfs.Download), ReasonStale)
}

func TestReasonOfOtherErrors(t *testing.T) {
	if r := ReasonOf(nil); r != "" {
		t.Errorf("ReasonOf(nil) = %q", r)
	}
	if r := ReasonOf(errors.New("boom")); r != "" {
		t.Errorf("ReasonOf(other) = %q", r)
	}
	if errors.Is(errors.New("authz: denied"), ErrDenied) {
		t.Error("an unrelated error with the same text must not be ErrDenied")
	}
}
