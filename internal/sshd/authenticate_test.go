package sshd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/token"
)

const testBase = "https://lfs.example.com"

func testSigner(t *testing.T) *token.Signer {
	t.Helper()
	secret := make([]byte, token.MinKeyLength)
	for i := range secret {
		secret[i] = byte(i)
	}
	s, err := token.NewSigner([]token.Key{{ID: "k1", Secret: secret}}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// grantStore returns a ready store with repo r1 at acme/assets (alias
// acme/old-assets), r2 at acme/other, and these identities: writer and reader
// on r1, other-writer on r2 only, and inactive, which holds admin on r1.
func grantStore(t *testing.T) *datastore.Store {
	t.Helper()
	person := func(id string, active bool) datastore.Identity {
		return datastore.Identity{ID: id, Kind: datastore.KindPerson, Active: active}
	}
	snap, err := datastore.NewSnapshot(datastore.Data{
		Identities: []datastore.Identity{person("writer", true), person("reader", true), person("other-writer", true), person("inactive", false)},
		Repos: []datastore.Repo{
			{ID: "r1", Path: "acme/assets", Aliases: []string{"acme/old-assets"}},
			{ID: "r2", Path: "acme/other"},
		},
		Grants: []datastore.Grant{
			{IdentityID: "writer", RepoID: "r1", Level: datastore.LevelWrite},
			{IdentityID: "reader", RepoID: "r1", Level: datastore.LevelRead},
			{IdentityID: "other-writer", RepoID: "r2", Level: datastore.LevelWrite},
			{IdentityID: "inactive", RepoID: "r1", Level: datastore.LevelAdmin},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	st := datastore.NewStore(time.Hour, datastore.DefaultLimits)
	if err := st.Swap(st.StartSync(), snap); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestAuthenticateIssuesScopedToken(t *testing.T) {
	signer := testSigner(t)
	var logs bytes.Buffer
	a := NewAuthenticator(authz.New(grantStore(t)), signer, testBase, slog.New(slog.NewTextHandler(&logs, nil)))
	for _, tt := range []struct {
		id, repo, href string
		op             lfs.Operation
	}{
		{"writer", "acme/assets", testBase + "/acme/assets", lfs.Upload},
		{"writer", "acme/assets", testBase + "/acme/assets", lfs.Download},
		{"reader", "acme/assets", testBase + "/acme/assets", lfs.Download},
		{"writer", "acme/old-assets", testBase + "/acme/old-assets", lfs.Upload},
	} {
		out, err := a.Handle(context.Background(), tt.id, Command{Name: CmdAuthenticate, Repo: tt.repo, Op: tt.op})
		if err != nil {
			t.Fatalf("%s %s %s: %v", tt.id, tt.repo, tt.op, err)
		}
		if !bytes.HasSuffix(out, []byte("}\n")) {
			t.Errorf("output does not end in a newline: %q", out)
		}
		var got struct {
			Href      string            `json:"href"`
			Header    map[string]string `json:"header"`
			ExpiresIn int64             `json:"expires_in"`
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
		if got.Href != tt.href || got.ExpiresIn != 900 || len(got.Header) != 1 {
			t.Errorf("response = %+v", got)
		}
		tok, ok := strings.CutPrefix(got.Header["Authorization"], "Bearer ")
		if !ok {
			t.Fatalf("authorization header = %q", got.Header["Authorization"])
		}
		c, err := signer.Verify(tok, "r1", tt.op)
		if err != nil || c.Subject != tt.id {
			t.Errorf("token claims = %+v, %v", c, err)
		}
		if strings.Contains(logs.String(), tok) {
			t.Fatal("token logged")
		}
	}
	if !strings.Contains(logs.String(), "token issued") || !strings.Contains(logs.String(), "repo_id=r1") {
		t.Errorf("issue not logged: %s", logs.String())
	}
}

func TestAuthenticateRefusals(t *testing.T) {
	a := NewAuthenticator(authz.New(grantStore(t)), testSigner(t), testBase, quiet())
	for _, tt := range []struct {
		name, id, repo string
		op             lfs.Operation
	}{
		{"read grant cannot upload", "reader", "acme/assets", lfs.Upload},
		{"grant on another repo", "other-writer", "acme/assets", lfs.Download},
		{"no grant at all", "writer", "acme/other", lfs.Download},
		{"unknown repo", "writer", "acme/missing", lfs.Download},
		{"inactive identity", "inactive", "acme/assets", lfs.Download},
		{"unknown identity", "nobody", "acme/assets", lfs.Download},
	} {
		out, err := a.Handle(context.Background(), tt.id, Command{Name: CmdAuthenticate, Repo: tt.repo, Op: tt.op})
		if !errors.Is(err, authz.ErrDenied) || out != nil {
			t.Errorf("%s: out = %q, err = %v", tt.name, out, err)
		}
	}
	notReady := NewAuthenticator(authz.New(datastore.NewStore(time.Hour, datastore.DefaultLimits)), testSigner(t), testBase, quiet())
	if _, err := notReady.Handle(context.Background(), "writer", Command{Name: CmdAuthenticate, Repo: "acme/assets", Op: lfs.Download}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("store not ready: err = %v", err)
	}
}

func TestAuthenticateRefusesTransfer(t *testing.T) {
	a := NewAuthenticator(authz.New(grantStore(t)), testSigner(t), testBase, quiet())
	out, err := a.Handle(context.Background(), "writer", Command{Name: CmdTransfer, Repo: "acme/assets", Op: lfs.Upload})
	if !errors.Is(err, ErrUnsupported) || out != nil {
		t.Fatalf("out = %q, err = %v", out, err)
	}
}
