package sshd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/telemetry"
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

// session returns a Session for id whose log records go to logs as JSON.
func session(id string, logs *syncBuffer) Session {
	return Session{IdentityID: id, IdentityKind: "person", Log: slog.New(slog.NewJSONHandler(logs, nil)).With("identity", id)}
}

// observedRec returns a Recorder and the reader that sees what it records.
func observedRec() (*telemetry.Recorder, *sdkmetric.ManualReader) {
	r := sdkmetric.NewManualReader()
	return telemetry.NewRecorder(sdkmetric.NewMeterProvider(sdkmetric.WithReader(r))), r
}

func TestAuthenticateIssuesScopedToken(t *testing.T) {
	signer := testSigner(t)
	logs := &syncBuffer{}
	rec, metrics := observedRec()
	recorded := tracetest.NewSpanRecorder()
	spans := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorded))
	a := NewAuthenticator(authz.New(grantStore(t)), signer, testBase, rec)
	for i, tt := range []struct {
		id, repo, href string
		op             lfs.Operation
	}{
		{"writer", "acme/assets", testBase + "/acme/assets", lfs.Upload},
		{"writer", "acme/assets", testBase + "/acme/assets", lfs.Download},
		{"reader", "acme/assets", testBase + "/acme/assets", lfs.Download},
		{"writer", "acme/old-assets", testBase + "/acme/old-assets", lfs.Upload},
	} {
		ctx, span := spans.Tracer("test").Start(context.Background(), "ssh exec")
		out, err := a.Handle(ctx, session(tt.id, logs), Command{Name: CmdAuthenticate, Repo: tt.repo, Op: tt.op})
		span.End()
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
		if strings.Contains(logs.String(), tok) || strings.Contains(logs.String(), got.Href) {
			t.Fatal("token or href logged")
		}
		// The audit record names the token by its ID, so a later Batch
		// request carrying it can be tied back to this issue.
		rs := logs.records(t, "token issued")
		if len(rs) != i+1 {
			t.Fatalf("%d issue records after %d issues", len(rs), i+1)
		}
		r := rs[i]
		checkFields(t, r, map[string]string{
			"identity":  tt.id,
			"token_id":  c.ID,
			"repo":      tt.repo,
			"repo_id":   "r1",
			"operation": string(tt.op),
			"expires":   time.Unix(c.Expires, 0).UTC().Format(time.RFC3339),
		})
		// The command's span names the token too, and the repo it is for.
		attrs := attribute.NewSet(recorded.Ended()[i].Attributes()...)
		tokenID, _ := attrs.Value(telemetry.AttrTokenID)
		repoID, _ := attrs.Value(telemetry.AttrRepoID)
		if tokenID.AsString() != c.ID || repoID.AsString() != "r1" {
			t.Errorf("span attributes = %v", attrs.ToSlice())
		}
	}
	got := counts(t, metrics, telemetry.MetricTokensIssued)
	want := map[string]int64{
		"operation=upload,repo=r1,user=writer":   2,
		"operation=download,repo=r1,user=writer": 1,
		"operation=download,repo=r1,user=reader": 1,
	}
	if len(got) != len(want) {
		t.Errorf("tokens issued = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("tokens issued{%s} = %d, want %d", k, got[k], v)
		}
	}
}

// Refusals are reported by the server loop, not here: Handle returns the
// denial with its reason and records nothing itself.
func TestAuthenticateRefusals(t *testing.T) {
	rec, metrics := observedRec()
	logs := &syncBuffer{}
	a := NewAuthenticator(authz.New(grantStore(t)), testSigner(t), testBase, rec)
	for _, tt := range []struct {
		name, id, repo string
		op             lfs.Operation
		reason         authz.Reason
	}{
		{"read grant cannot upload", "reader", "acme/assets", lfs.Upload, authz.ReasonInsufficientGrant},
		{"grant on another repo", "other-writer", "acme/assets", lfs.Download, authz.ReasonInsufficientGrant},
		{"no grant at all", "writer", "acme/other", lfs.Download, authz.ReasonInsufficientGrant},
		{"unknown repo", "writer", "acme/missing", lfs.Download, authz.ReasonUnknownRepo},
		{"inactive identity", "inactive", "acme/assets", lfs.Download, authz.ReasonInactiveIdentity},
		{"unknown identity", "nobody", "acme/assets", lfs.Download, authz.ReasonUnknownIdentity},
	} {
		out, err := a.Handle(context.Background(), session(tt.id, logs), Command{Name: CmdAuthenticate, Repo: tt.repo, Op: tt.op})
		if !errors.Is(err, authz.ErrDenied) || authz.ReasonOf(err) != tt.reason || out != nil {
			t.Errorf("%s: out = %q, err = %v (%s)", tt.name, out, err, authz.ReasonOf(err))
		}
	}
	notReady := NewAuthenticator(authz.New(datastore.NewStore(time.Hour, datastore.DefaultLimits)), testSigner(t), testBase, rec)
	if _, err := notReady.Handle(context.Background(), session("writer", logs), Command{Name: CmdAuthenticate, Repo: "acme/assets", Op: lfs.Download}); authz.ReasonOf(err) != authz.ReasonNotReady {
		t.Errorf("store not ready: err = %v", err)
	}
	if logs.String() != "" || len(counts(t, metrics, telemetry.MetricTokensIssued)) != 0 {
		t.Errorf("refusal recorded as an issue: %s", logs.String())
	}
}

// If no token ID can be drawn, nothing is issued: no empty bearer token, no
// issue record.
func TestAuthenticateMintFailure(t *testing.T) {
	signer := testSigner(t)
	signer.Rand = iotest.ErrReader(errors.New("no entropy"))
	rec, metrics := observedRec()
	logs := &syncBuffer{}
	a := NewAuthenticator(authz.New(grantStore(t)), signer, testBase, rec)
	out, err := a.Handle(context.Background(), session("writer", logs), Command{Name: CmdAuthenticate, Repo: "acme/assets", Op: lfs.Upload})
	if err == nil || errors.Is(err, authz.ErrDenied) || out != nil {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	if logs.String() != "" || len(counts(t, metrics, telemetry.MetricTokensIssued)) != 0 {
		t.Errorf("failed mint recorded as an issue: %s", logs.String())
	}
}

func TestAuthenticateRefusesTransfer(t *testing.T) {
	a := NewAuthenticator(authz.New(grantStore(t)), testSigner(t), testBase, noRec())
	out, err := a.Handle(context.Background(), session("writer", &syncBuffer{}), Command{Name: CmdTransfer, Repo: "acme/assets", Op: lfs.Upload})
	if !errors.Is(err, ErrUnsupported) || out != nil {
		t.Fatalf("out = %q, err = %v", out, err)
	}
}
