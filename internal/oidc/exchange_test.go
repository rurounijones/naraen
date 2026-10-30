package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/telemetry"
	"github.com/rurounijones/naraen/internal/token"
)

const (
	testIssuer = "https://token.actions.githubusercontent.com"
	testAud    = "https://lfs.example.com"
)

var exchangeNow = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

type exchangeFixture struct {
	x       *Exchange
	store   *datastore.Store
	key     *signer
	mux     *http.ServeMux
	logs    *bytes.Buffer
	metrics *sdkmetric.ManualReader
}

// newExchange trusts two entries for one issuer: key "a" for audience
// testAud, and key "b" for another audience, so a token is checked against
// the entry whose key signed it. workload:r1 may read r1 and r2;
// workload:r9 has no identity.
func newExchange(t *testing.T) *exchangeFixture {
	t.Helper()
	a, b := newES256(t, "a"), newES256(t, "b")
	workload := func(repo string) datastore.Identity {
		return datastore.Identity{ID: WorkloadPrefix + repo, Kind: datastore.KindWorkload, Active: true}
	}
	snap, err := datastore.NewSnapshot(datastore.Data{
		Identities: []datastore.Identity{workload("r1")},
		Repos: []datastore.Repo{
			{ID: "r1", Path: "acme/assets"}, {ID: "r2", Path: "acme/other"}, {ID: "r9", Path: "acme/nobody"},
		},
		Grants: []datastore.Grant{
			{IdentityID: WorkloadPrefix + "r1", RepoID: "r1", Level: datastore.LevelRead},
			{IdentityID: WorkloadPrefix + "r1", RepoID: "r2", Level: datastore.LevelRead},
		},
		Trusts: []datastore.WorkloadTrust{
			{Issuer: testIssuer, Audience: "https://elsewhere.example.com", JWKS: jwks(b.jwk()), RepoClaim: "repository_id", MaxLevel: datastore.LevelRead},
			{Issuer: testIssuer, Audience: testAud, JWKS: jwks(a.jwk()), RepoClaim: "repository_id", MaxLevel: datastore.LevelRead},
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
	logs := &bytes.Buffer{}
	reader := sdkmetric.NewManualReader()
	x := &Exchange{
		Store: st, Authz: authz.New(st), Tokens: tokens, Base: "https://lfs.example.com",
		Rec: telemetry.NewRecorder(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))),
		Log: slog.New(slog.NewJSONHandler(logs, nil)),
		Now: func() time.Time { return exchangeNow },
	}
	mux := http.NewServeMux()
	mux.Handle("POST /{owner}/{repo}/ci/token", x)
	return &exchangeFixture{x: x, store: st, key: a, mux: mux, logs: logs, metrics: reader}
}

func ciClaims(repo string) map[string]any {
	return map[string]any{
		"iss": testIssuer, "aud": testAud, "repository_id": repo,
		"exp": exchangeNow.Add(5 * time.Minute).Unix(), "sub": "repo:acme/assets:ref:refs/heads/main",
	}
}

func (f *exchangeFixture) post(path, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func TestExchangeIssuesReadToken(t *testing.T) {
	f := newExchange(t)
	w := f.post("/Acme/Assets.git/ci/token", "Bearer "+f.key.sign(t, nil, ciClaims("r1")))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp exchangeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Href != "https://lfs.example.com/acme/assets" || resp.ExpiresIn != 900 {
		t.Errorf("response = %+v", resp)
	}
	tok, _ := token.Bearer(resp.Header["Authorization"])
	c, err := f.x.Tokens.Verify(tok, "r1", lfs.Download)
	if err != nil || c.Subject != "workload:r1" {
		t.Fatalf("token claims = %+v, %v", c, err)
	}
	if _, err := f.x.Tokens.Verify(tok, "r1", lfs.Upload); err == nil {
		t.Error("an exchanged token allows upload")
	}
	logs := f.logs.String()
	for _, want := range []string{
		`"msg":"token issued"`, `"identity":"workload:r1"`, `"identity_type":"workload"`,
		`"issuer":"` + testIssuer + `"`, `"token_id":"` + c.ID + `"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %s: %s", want, logs)
		}
	}
	if strings.Contains(logs, tok) {
		t.Error("token logged")
	}
	if got := f.counters(t)["lfs.tokens.issued{operation=download,repo=r1,user=workload:r1}"]; got != 1 {
		t.Errorf("tokens issued = %d", got)
	}
}

func TestExchangeRefusals(t *testing.T) {
	f := newExchange(t)
	expired := ciClaims("r1")
	expired["exp"] = exchangeNow.Add(-time.Minute).Unix()
	otherAud := ciClaims("r1")
	otherAud["aud"] = "https://nowhere.example.com"
	noIss := ciClaims("r1")
	delete(noIss, "iss")
	otherIss := ciClaims("r1")
	otherIss["iss"] = "https://evil.example.com"
	stranger := newES256(t, "a")
	for name, tt := range map[string]struct {
		path, auth string
		status     int
		reason     string
	}{
		"no token":         {"/acme/assets/ci/token", "", 401, "bad_oidc"},
		"not a jwt":        {"/acme/assets/ci/token", "Bearer abc", 401, "bad_oidc"},
		"expired":          {"/acme/assets/ci/token", "Bearer " + f.key.sign(t, nil, expired), 401, "bad_oidc"},
		"other audience":   {"/acme/assets/ci/token", "Bearer " + f.key.sign(t, nil, otherAud), 401, "bad_oidc"},
		"no issuer":        {"/acme/assets/ci/token", "Bearer " + f.key.sign(t, nil, noIss), 401, "bad_oidc"},
		"untrusted issuer": {"/acme/assets/ci/token", "Bearer " + f.key.sign(t, nil, otherIss), 401, "bad_oidc"},
		"forged key":       {"/acme/assets/ci/token", "Bearer " + stranger.sign(t, nil, ciClaims("r1")), 401, "bad_oidc"},
		"other repo's url": {"/acme/other/ci/token", "Bearer " + f.key.sign(t, nil, ciClaims("r1")), 403, "repo_mismatch"},
		"no workload":      {"/acme/nobody/ci/token", "Bearer " + f.key.sign(t, nil, ciClaims("r9")), 403, "unknown_identity"},
		"unknown repo url": {"/acme/missing/ci/token", "Bearer " + f.key.sign(t, nil, ciClaims("r1")), 403, "unknown_repo"},
	} {
		t.Run(name, func(t *testing.T) {
			f.logs.Reset()
			w := f.post(tt.path, tt.auth)
			if w.Code != tt.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tt.status, w.Body)
			}
			msg := map[int]string{401: `{"message":"unauthorized"}`, 403: `{"message":"forbidden"}`}[tt.status]
			if strings.TrimSpace(w.Body.String()) != msg {
				t.Errorf("body %s, want %s", w.Body, msg)
			}
			if !strings.Contains(f.logs.String(), `"reason":"`+tt.reason+`"`) {
				t.Errorf("log lacks reason %s: %s", tt.reason, f.logs.String())
			}
		})
	}
	if got := f.counters(t)["lfs.auth.failures{identity_type=workload,reason=bad_oidc}"]; got != 7 {
		t.Errorf("bad_oidc failures = %d", got)
	}
}

func TestExchangeUnavailableAndFailing(t *testing.T) {
	f := newExchange(t)
	tok := "Bearer " + f.key.sign(t, nil, ciClaims("r1"))
	f.x.Tokens.Rand = iotest.ErrReader(errors.New("no entropy"))
	if w := f.post("/acme/assets/ci/token", tok); w.Code != http.StatusInternalServerError {
		t.Errorf("mint failure: %d", w.Code)
	}
	f.x.Store = datastore.NewStore(time.Hour, datastore.DefaultLimits)
	if w := f.post("/acme/assets/ci/token", tok); w.Code != http.StatusServiceUnavailable {
		t.Errorf("not ready: %d", w.Code)
	}
}

// counters returns each counter point as "name{k=v,...}" to its value.
func (f *exchangeFixture) counters(t *testing.T) map[string]int64 {
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
