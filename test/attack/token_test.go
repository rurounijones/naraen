package attack

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric/noop"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/batch"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/httpapi"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/oid"
	"github.com/rurounijones/naraen/internal/storage"
	"github.com/rurounijones/naraen/internal/telemetry"
	"github.com/rurounijones/naraen/internal/token"
)

// openBucket holds nothing and issues a link for anything, so the only thing
// standing between a request and a link is the handler's own checks.
type openBucket struct{ links int }

func (b *openBucket) link() (storage.Link, error) {
	b.links++
	return storage.Link{URL: "https://s3.test/x", Expires: time.Now().Add(time.Minute)}, nil
}

func (b *openBucket) PresignGet(context.Context, string, oid.OID, string) (storage.Link, error) {
	return b.link()
}

func (b *openBucket) PresignPut(context.Context, string, oid.OID, int64, string) (storage.Link, error) {
	return b.link()
}

// Stat reports nothing stored, so every upload gets a link.
func (*openBucket) Stat(context.Context, string, oid.OID) (int64, bool, error) { return 0, false, nil }

type batchTarget struct {
	srv     http.Handler
	tokens  *token.Signer
	clock   *time.Time
	objects *openBucket
}

// batchServer serves the real mux over two repos, where
// mallory may write to repo A only.
func batchServer(t *testing.T) *batchTarget {
	t.Helper()
	snap, err := datastore.NewSnapshot(datastore.Data{
		Identities: []datastore.Identity{{ID: "mallory", Kind: datastore.KindPerson, Active: true}},
		Repos: []datastore.Repo{
			{ID: "A", Path: "acme/a", Aliases: []string{"acme/a-old"}},
			{ID: "B", Path: "acme/b"},
		},
		Grants: []datastore.Grant{{IdentityID: "mallory", RepoID: "A", Level: datastore.LevelWrite}},
	})
	if err != nil {
		t.Fatal(err)
	}
	st := datastore.NewStore(time.Hour, datastore.DefaultLimits)
	if err := st.Swap(st.StartSync(), snap); err != nil {
		t.Fatal(err)
	}
	tokens, err := token.NewSigner([]token.Key{{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdef")}}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tokens.Now = func() time.Time { return now }
	objects := &openBucket{}
	h := &batch.Handler{
		Store: st, Authz: authz.New(st), Tokens: tokens,
		Objects: objects,
		Rec:     telemetry.NewRecorder(noop.NewMeterProvider()),
		Log:     slog.New(slog.DiscardHandler),
		Rand:    strings.NewReader(strings.Repeat("x", 1<<12)),
	}
	return &batchTarget{srv: httpapi.Handler(st, h, http.NotFoundHandler(), nil, tracenoop.NewTracerProvider()), tokens: tokens, clock: &now, objects: objects}
}

func (b *batchTarget) post(path, tok, body string) int {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	b.srv.ServeHTTP(w, r)
	return w.Code
}

func uploadBody(n int) string {
	objs := make([]string, n)
	for i := range objs {
		objs[i] = fmt.Sprintf(`{"oid":"%064x","size":1}`, i)
	}
	return `{"operation":"upload","objects":[` + strings.Join(objs, ",") + `]}`
}

// A token is good only at the repo it was minted for, reached by any of its
// names, for the operation it names, until it expires, and unaltered.
func TestBatchTokenAttacks(t *testing.T) {
	b := batchServer(t)
	tokA, _, err := b.tokens.Mint("mallory", "A", lfs.Upload)
	if err != nil {
		t.Fatal(err)
	}
	one := uploadBody(1)
	if code := b.post("/acme/a/objects/batch", tokA, one); code != http.StatusOK {
		t.Fatalf("baseline: %d", code)
	}
	if code := b.post("/acme/a-old/objects/batch", tokA, one); code != http.StatusOK {
		t.Errorf("alias of the token's own repo: %d", code)
	}

	// Edit the payload to name repo B and keep the signature.
	parts := strings.Split(tokA, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	parts[2] = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), `"rid":"A"`, `"rid":"B"`, 1)))
	edited := strings.Join(parts, ".")

	for name, tt := range map[string]struct{ path, tok string }{
		"reused at another repo":  {"/acme/b/objects/batch", tokA},
		"edited to another repo":  {"/acme/b/objects/batch", edited},
		"edited, at its own repo": {"/acme/a/objects/batch", edited},
		"at an unknown repo":      {"/acme/c/objects/batch", tokA},
		"path trick":              {"/acme/..%2Fb/objects/batch", tokA},
	} {
		if code := b.post(tt.path, tt.tok, one); code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, code)
		}
	}

	*b.clock = b.clock.Add(15 * time.Minute)
	if code := b.post("/acme/a/objects/batch", tokA, one); code != http.StatusUnauthorized {
		t.Errorf("expired token: %d, want 401", code)
	}
	if b.objects.links != 2 {
		t.Errorf("links issued = %d, want only the two allowed requests", b.objects.links)
	}
}

// A batch over the object cap is refused before storage is touched.
func TestOversizedBatch(t *testing.T) {
	b := batchServer(t)
	tok, _, err := b.tokens.Mint("mallory", "A", lfs.Upload)
	if err != nil {
		t.Fatal(err)
	}
	if code := b.post("/acme/a/objects/batch", tok, uploadBody(batch.MaxObjects+1)); code != http.StatusUnprocessableEntity {
		t.Errorf("oversized batch: %d, want 422", code)
	}
	if b.objects.links != 0 {
		t.Errorf("links issued = %d", b.objects.links)
	}
}
