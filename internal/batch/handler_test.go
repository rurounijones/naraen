package batch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/oid"
	"github.com/rurounijones/naraen/internal/storage"
	"github.com/rurounijones/naraen/internal/telemetry"
	"github.com/rurounijones/naraen/internal/token"
)

// fakeObjects is an in-memory store. Objects listed in fail make Stat fail;
// objects listed in presignFail make pre-signing fail.
type fakeObjects struct {
	mu          sync.Mutex
	stored      map[oid.OID]int64
	fail        map[oid.OID]bool
	presignFail map[oid.OID]bool
	requestIDs  map[string]bool
	repos       map[string]bool
}

func (f *fakeObjects) note(repoID, requestID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requestIDs[requestID] = true
	f.repos[repoID] = true
}

func (f *fakeObjects) link(kind, repoID string, id oid.OID, requestID string) (storage.Link, error) {
	f.note(repoID, requestID)
	if f.presignFail[id] {
		return storage.Link{}, errors.New("presign failed")
	}
	return storage.Link{
		URL:     fmt.Sprintf("https://s3.test/%s/%s?%s&x-lfs-req=%s", repoID, id, kind, requestID),
		Headers: map[string]string{"X-Kind": kind},
		Expires: time.Date(2026, 10, 31, 12, 15, 0, 0, time.FixedZone("x", 3600)),
	}, nil
}

func (f *fakeObjects) PresignGet(_ context.Context, repoID string, id oid.OID, requestID string) (storage.Link, error) {
	return f.link("get", repoID, id, requestID)
}

func (f *fakeObjects) PresignPut(_ context.Context, repoID string, id oid.OID, _ int64, requestID string) (storage.Link, error) {
	return f.link("put", repoID, id, requestID)
}

func (f *fakeObjects) Stat(_ context.Context, _ string, id oid.OID) (int64, bool, error) {
	if f.fail[id] {
		return 0, false, errors.New("head failed")
	}
	size, ok := f.stored[id]
	return size, ok, nil
}

func oidOf(c byte) oid.OID { return oid.OID(strings.Repeat(string(c), 64)) }

type fixture struct {
	store   *datastore.Store
	tokens  *token.Signer
	objects *fakeObjects
	handler *Handler
	mux     *http.ServeMux
	logs    *bytes.Buffer
	metrics *sdkmetric.ManualReader
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	person := func(id string) datastore.Identity {
		return datastore.Identity{ID: id, Kind: datastore.KindPerson, Active: true}
	}
	snap, err := datastore.NewSnapshot(datastore.Data{
		Identities: []datastore.Identity{person("writer"), person("reader")},
		Repos: []datastore.Repo{
			{ID: "r1", Path: "acme/assets", Aliases: []string{"acme/old-assets"}},
			{ID: "r2", Path: "acme/other"},
		},
		Grants: []datastore.Grant{
			{IdentityID: "writer", RepoID: "r1", Level: datastore.LevelWrite},
			{IdentityID: "writer", RepoID: "r2", Level: datastore.LevelWrite},
			{IdentityID: "reader", RepoID: "r1", Level: datastore.LevelRead},
		},
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
	objects := &fakeObjects{
		stored:      map[oid.OID]int64{oidOf('a'): 10, oidOf('b'): 20},
		fail:        map[oid.OID]bool{},
		presignFail: map[oid.OID]bool{},
		requestIDs:  map[string]bool{},
		repos:       map[string]bool{},
	}
	logs := &bytes.Buffer{}
	reader := sdkmetric.NewManualReader()
	h := &Handler{
		Store:   st,
		Authz:   authz.New(st),
		Tokens:  tokens,
		Objects: objects,
		Rec:     telemetry.NewRecorder(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))),
		Log:     slog.New(slog.NewJSONHandler(logs, nil)),
		Rand:    strings.NewReader(strings.Repeat("r", 1<<12)),
	}
	mux := http.NewServeMux()
	mux.Handle("POST /{owner}/{repo}/objects/batch", h)
	return &fixture{store: st, tokens: tokens, objects: objects, handler: h, mux: mux, logs: logs, metrics: reader}
}

func (f *fixture) mint(t *testing.T, sub, repoID string, op lfs.Operation) string {
	t.Helper()
	tok, _, err := f.tokens.Mint(sub, repoID, op)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func batchBody(op lfs.Operation, objects ...Object) string {
	var parts []string
	for _, o := range objects {
		parts = append(parts, fmt.Sprintf(`{"oid":%q,"size":%d}`, o.OID, o.Size))
	}
	return fmt.Sprintf(`{"operation":%q,"transfers":["basic"],"objects":[%s]}`, op, strings.Join(parts, ","))
}

func (f *fixture) do(path, auth, reqBody string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(reqBody))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) response {
	t.Helper()
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != ContentType {
		t.Fatalf("status %d, type %q: %s", w.Code, w.Header().Get("Content-Type"), w.Body)
	}
	var resp response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Transfer != "basic" || resp.HashAlgo != "sha256" {
		t.Errorf("transfer %q, hash %q", resp.Transfer, resp.HashAlgo)
	}
	return resp
}

// counters returns each counter point as "name{k=v,...}" to its value.
func (f *fixture) counters(t *testing.T) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := f.metrics.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
				for _, dp := range sum.DataPoints {
					var kv []string
					for _, a := range dp.Attributes.ToSlice() {
						kv = append(kv, string(a.Key)+"="+a.Value.AsString())
					}
					got[m.Name+"{"+strings.Join(kv, ",")+"}"] = dp.Value
				}
			}
		}
	}
	return got
}

func TestUpload(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(t, "writer", "r1", lfs.Upload)
	w := f.do("/acme/assets/objects/batch", "Bearer "+tok,
		batchBody(lfs.Upload, Object{oidOf('a'), 10}, Object{oidOf('c'), 30}))
	resp := decode(t, w)
	if len(resp.Objects) != 2 {
		t.Fatalf("objects = %+v", resp.Objects)
	}
	stored, fresh := resp.Objects[0], resp.Objects[1]
	if stored.OID != oidOf('a') || stored.Actions != nil || stored.Error != nil || stored.Authenticated {
		t.Errorf("stored object must get no action: %+v", stored)
	}
	up, ok := fresh.Actions["upload"]
	if fresh.OID != oidOf('c') || fresh.Size != 30 || !ok || !fresh.Authenticated || len(fresh.Actions) != 1 {
		t.Fatalf("new object = %+v", fresh)
	}
	if !strings.HasPrefix(up.Href, "https://s3.test/r1/"+string(oidOf('c'))+"?put") ||
		up.Header["X-Kind"] != "put" || up.ExpiresAt.Location() != time.UTC {
		t.Errorf("upload action = %+v", up)
	}
	if len(f.objects.requestIDs) != 1 {
		t.Errorf("request IDs = %v, want one per batch", f.objects.requestIDs)
	}
	logs := f.logs.String()
	for _, want := range []string{
		`"msg":"links issued"`, `"identity":"writer"`, `"token_id":"`, `"request_id":"`,
		`"repo_id":"r1"`, `"objects":2`, `"links":1`, `"bytes":30`, `"identity_type":"person"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %s: %s", want, logs)
		}
	}
	if strings.Contains(logs, "https://") || strings.Contains(logs, tok) {
		t.Errorf("log holds a link or the token: %s", logs)
	}
	got := f.counters(t)
	for k, v := range map[string]int64{
		"lfs.links.issued{operation=upload,outcome=issued,repo=r1,user=writer}":  1,
		"lfs.links.issued{operation=upload,outcome=present,repo=r1,user=writer}": 1,
		"lfs.bytes.requested{operation=upload,repo=r1,user=writer}":              30,
	} {
		if got[k] != v {
			t.Errorf("%s = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
}

func TestDownload(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(t, "reader", "r1", lfs.Download)
	// The alias names the same repo, so the token for r1 is good there.
	w := f.do("/acme/old-assets/objects/batch", "Bearer "+tok, batchBody(lfs.Download,
		Object{oidOf('a'), 10}, Object{oidOf('c'), 30}, Object{oidOf('b'), 21}))
	resp := decode(t, w)
	if len(resp.Objects) != 3 {
		t.Fatalf("objects = %+v", resp.Objects)
	}
	if d, ok := resp.Objects[0].Actions["download"]; !ok || !strings.Contains(d.Href, "?get") || !resp.Objects[0].Authenticated {
		t.Errorf("stored object = %+v", resp.Objects[0])
	}
	if e := resp.Objects[1].Error; e == nil || e.Code != http.StatusNotFound || resp.Objects[1].Actions != nil {
		t.Errorf("missing object = %+v", resp.Objects[1])
	}
	if e := resp.Objects[2].Error; e == nil || e.Code != http.StatusUnprocessableEntity || resp.Objects[2].Actions != nil {
		t.Errorf("wrong size = %+v", resp.Objects[2])
	}
	got := f.counters(t)
	for k, v := range map[string]int64{
		"lfs.links.issued{operation=download,outcome=issued,repo=r1,user=reader}":   1,
		"lfs.links.issued{operation=download,outcome=missing,repo=r1,user=reader}":  1,
		"lfs.links.issued{operation=download,outcome=mismatch,repo=r1,user=reader}": 1,
		"lfs.bytes.requested{operation=download,repo=r1,user=reader}":               10,
	} {
		if got[k] != v {
			t.Errorf("%s = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
}

// Storage failures become per-object errors; the rest of the batch is
// answered.
func TestStorageFailures(t *testing.T) {
	f := newFixture(t)
	f.objects.fail[oidOf('a')] = true
	f.objects.presignFail[oidOf('c')] = true
	tok := f.mint(t, "writer", "r1", lfs.Upload)
	resp := decode(t, f.do("/acme/assets/objects/batch", "Bearer "+tok,
		batchBody(lfs.Upload, Object{oidOf('a'), 10}, Object{oidOf('c'), 30}, Object{oidOf('d'), 40})))
	for i, code := range []int{http.StatusInternalServerError, http.StatusInternalServerError, 0} {
		o := resp.Objects[i]
		if (code == 0) != (o.Error == nil) || (o.Error != nil && o.Error.Code != code) {
			t.Errorf("object %d = %+v, want error code %d", i, o, code)
		}
	}
	if !strings.Contains(f.logs.String(), `"msg":"storage failed"`) || !strings.Contains(f.logs.String(), `"msg":"presign failed"`) {
		t.Errorf("failures not logged: %s", f.logs.String())
	}
	if got := f.counters(t)["lfs.links.issued{operation=upload,outcome=error,repo=r1,user=writer}"]; got != 2 {
		t.Errorf("error outcomes = %d", got)
	}
}

// A batch larger than the S3 concurrency cap is answered in full and in order.
func TestManyObjects(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(t, "writer", "r1", lfs.Upload)
	objects := make([]Object, 0, 3*statConcurrency)
	for i := range 3 * statConcurrency {
		objects = append(objects, Object{oid.OID(fmt.Sprintf("%064x", i+1)), int64(i)})
	}
	resp := decode(t, f.do("/acme/assets/objects/batch", "Bearer "+tok, batchBody(lfs.Upload, objects...)))
	for i, o := range resp.Objects {
		if o.OID != objects[i].OID || o.Actions["upload"].Href == "" {
			t.Fatalf("object %d = %+v", i, o)
		}
	}
}

// Every failure before the token is verified looks the same to the caller,
// so nothing reveals whether a repo exists.
func TestUnauthorized(t *testing.T) {
	f := newFixture(t)
	good := f.mint(t, "writer", "r1", lfs.Upload)
	other := f.mint(t, "writer", "r2", lfs.Upload)
	download := f.mint(t, "writer", "r1", lfs.Download)
	up := batchBody(lfs.Upload, Object{oidOf('c'), 1})
	for name, tt := range map[string]struct{ path, auth, reason string }{
		"no header":             {"/acme/assets/objects/batch", "", "bad_token"},
		"basic auth":            {"/acme/assets/objects/batch", "Basic Zm9vOmJhcg==", "bad_token"},
		"token at another repo": {"/acme/other/objects/batch", "Bearer " + good, "bad_token"},
		"other repo's token":    {"/acme/assets/objects/batch", "Bearer " + other, "bad_token"},
		"download token":        {"/acme/assets/objects/batch", "Bearer " + download, "bad_token"},
		"garbage token":         {"/acme/assets/objects/batch", "Bearer v1.k1.x.y", "bad_token"},
		"unknown repo":          {"/acme/missing/objects/batch", "Bearer " + good, "unknown_repo"},
		"bad path":              {"/acme/as%2Fsets/objects/batch", "Bearer " + good, "bad_path"},
	} {
		t.Run(name, func(t *testing.T) {
			f.logs.Reset()
			w := f.do(tt.path, tt.auth, up)
			if w.Code != http.StatusUnauthorized || strings.TrimSpace(w.Body.String()) != `{"message":"unauthorized"}` {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			if !strings.Contains(f.logs.String(), `"reason":"`+tt.reason+`"`) {
				t.Errorf("log lacks reason %s: %s", tt.reason, f.logs.String())
			}
		})
	}
	if len(f.objects.requestIDs) != 0 {
		t.Error("storage touched for an unauthorized request")
	}
	if got := f.counters(t)["lfs.auth.failures{identity_type=unknown,reason=bad_token}"]; got != 6 {
		t.Errorf("bad_token failures = %d", got)
	}
}

func TestForbidden(t *testing.T) {
	f := newFixture(t)
	up := batchBody(lfs.Upload, Object{oidOf('c'), 1})
	// A token minted for an upload the grant does not allow.
	w := f.do("/acme/assets/objects/batch", "Bearer "+f.mint(t, "reader", "r1", lfs.Upload), up)
	if w.Code != http.StatusForbidden || !strings.Contains(f.logs.String(), `"reason":"insufficient_grant"`) {
		t.Errorf("read grant uploading: %d %s", w.Code, f.logs.String())
	}
	// A grant revoked after the token was minted stops the next request.
	tok := f.mint(t, "writer", "r1", lfs.Upload)
	f.store.Narrow(datastore.Narrowing{DropGrants: []datastore.GrantRef{{IdentityID: "writer", RepoID: "r1"}}})
	if w := f.do("/acme/assets/objects/batch", "Bearer "+tok, up); w.Code != http.StatusForbidden {
		t.Errorf("revoked grant: %d", w.Code)
	}
	// A token whose subject has left the snapshot is counted as unknown.
	f.store.Narrow(datastore.Narrowing{DeactivateIdentities: []string{"reader"}})
	f.do("/acme/assets/objects/batch", "Bearer "+f.mint(t, "reader", "r1", lfs.Download), batchBody(lfs.Download, Object{oidOf('a'), 10}))
	if got := f.counters(t)["lfs.auth.failures{identity_type=unknown,reason=inactive_identity}"]; got != 1 {
		t.Errorf("inactive identity failures = %d", got)
	}
}

func TestInvalidAndUnavailable(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(t, "writer", "r1", lfs.Upload)
	if w := f.do("/acme/assets/objects/batch", "Bearer "+tok, `{"operation":"upload"}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid body: %d", w.Code)
	}
	f.handler.Rand = iotest.ErrReader(errors.New("no entropy"))
	if w := f.do("/acme/assets/objects/batch", "Bearer "+tok, batchBody(lfs.Upload, Object{oidOf('c'), 1})); w.Code != http.StatusInternalServerError {
		t.Errorf("no randomness: %d", w.Code)
	}
	f.handler.Store = datastore.NewStore(time.Hour, datastore.DefaultLimits)
	if w := f.do("/acme/assets/objects/batch", "Bearer "+tok, batchBody(lfs.Upload, Object{oidOf('c'), 1})); w.Code != http.StatusServiceUnavailable {
		t.Errorf("not ready: %d", w.Code)
	}
}

func TestUnconfigured(t *testing.T) {
	w := httptest.NewRecorder()
	Unconfigured().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/a/b/objects/batch", nil))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Content-Type") != ContentType {
		t.Errorf("status %d, type %q", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestBearer(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer abc":  "abc",
		"Bearer ":     "",
		"bearer abc":  "",
		"Bearer a b":  "",
		"Bearer a\tb": "",
		"Basic abc":   "",
		"":            "",
		"Bearerabc":   "",
	} {
		got, ok := Bearer(header)
		if got != want || ok != (want != "") {
			t.Errorf("Bearer(%q) = %q, %v", header, got, ok)
		}
	}
}

func FuzzBearer(f *testing.F) {
	for _, s := range []string{"Bearer abc", "Bearer ", "Basic x", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		tok, ok := Bearer(header)
		if ok && (tok == "" || strings.ContainsAny(tok, " \t") || "Bearer "+tok != header) {
			t.Fatalf("Bearer(%q) = %q", header, tok)
		}
	})
}
