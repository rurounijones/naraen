package github

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rurounijones/naraen/internal/datastore"
)

var syncNow = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// fakeGitHub serves the API endpoints a sync reads. routes maps a request
// path with its query to a response body; links adds a Link header.
type fakeGitHub struct {
	*httptest.Server
	appKey      *rsa.PrivateKey
	routes      map[string]string
	links       map[string]string
	status      map[string]int
	tokenStatus int
	tokenCalls  atomic.Int32
	// With etags set, API pages carry an ETag and a matching If-None-Match
	// is answered 304, as GitHub does; full and unchanged count each.
	etags     bool
	full      atomic.Int32
	unchanged atomic.Int32
	// inFlight and maxInFlight track concurrent API requests, each held
	// for delay.
	inFlight, maxInFlight atomic.Int32
	delay                 time.Duration
	// mu is held for reading while a request is served; see edit.
	mu sync.RWMutex
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGitHub{appKey: key, routes: map[string]string{}, links: map[string]string{}, status: map[string]int{}, tokenStatus: http.StatusCreated}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

// edit changes the fake while no request is being served, for a test that
// changes it after a failed sync: the requests that sync cancelled may still
// be arriving.
func (f *fakeGitHub) edit(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if r.Method == http.MethodPost && r.URL.Path == "/app/installations/99/access_tokens" {
		f.tokenCalls.Add(1)
		if !f.validAppJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
			http.Error(w, "bad jwt", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(f.tokenStatus)
		_, _ = fmt.Fprintf(w, `{"token":"inst-token","expires_at":%q}`, syncNow.Add(time.Hour).Format(time.RFC3339))
		return
	}
	key := r.URL.RequestURI()
	if key == "/jwks" {
		if s, ok := f.status[key]; ok {
			w.WriteHeader(s)
		}
		_, _ = w.Write([]byte(f.routes[key]))
		return
	}
	if r.Header.Get("Authorization") != "Bearer inst-token" || r.Header.Get("X-GitHub-Api-Version") == "" {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	raise(&f.maxInFlight, f.inFlight.Add(1))
	defer f.inFlight.Add(-1)
	time.Sleep(f.delay)
	body, ok := f.routes[key]
	if !ok {
		http.Error(w, "not found: "+key, http.StatusNotFound)
		return
	}
	if f.etags {
		sum := sha256.Sum256([]byte(body))
		etag := fmt.Sprintf(`"%x"`, sum[:8])
		if r.Header.Get("If-None-Match") == etag {
			f.unchanged.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		f.full.Add(1)
		w.Header().Set("ETag", etag)
	}
	if l, ok := f.links[key]; ok {
		w.Header().Set("Link", strings.ReplaceAll(l, "BASE", f.URL))
	}
	if s, ok := f.status[key]; ok {
		w.WriteHeader(s)
	}
	_, _ = w.Write([]byte(body))
}

// raise sets v to n if n is larger.
func raise(v *atomic.Int32, n int32) {
	for {
		m := v.Load()
		if n <= m || v.CompareAndSwap(m, n) {
			return
		}
	}
}

// validAppJWT checks the App JWT the way GitHub does: RS256 with the App's
// key, issued by the App, and lasting exactly ten minutes.
func (f *fakeGitHub) validAppJWT(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&f.appKey.PublicKey, crypto.SHA256, digest[:], sig) != nil {
		return false
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	// Nine minutes ahead plus the minute iat is backdated by: GitHub's
	// ten-minute maximum, used to the full.
	return json.Unmarshal(raw, &c) == nil && c.Iss == "12345" && c.Exp-c.Iat == 600
}

func (f *fakeGitHub) provider(audience string) *Provider {
	auth := &AppAuth{BaseURL: f.URL, AppID: "12345", InstallationID: "99", Key: f.appKey, HTTP: f.Client(), Now: func() time.Time { return syncNow }}
	return &Provider{
		Client:   &Client{BaseURL: f.URL, HTTP: f.Client(), Token: auth.Token},
		Org:      "acme",
		Audience: audience,
		JWKSURL:  f.URL + "/jwks",
		Now:      func() time.Time { return syncNow },
	}
}

// organisation fills the fake with a small organisation: two repos across
// two pages, members alice and bob, outside collaborator carol, and a
// read-only deploy key on acme/assets.
func (f *fakeGitHub) organisation(t *testing.T) (aliceKey, deployFP string) {
	t.Helper()
	alice, aliceFP := deployKey(t)
	deploy, deployFP := deployKey(t)
	f.routes["/installation/repositories?per_page=100"] = `{"total_count":2,"repositories":[{"id":100,"full_name":"acme/Assets"}]}`
	f.links["/installation/repositories?per_page=100"] = `<BASE/installation/repositories?per_page=100&page=2>; rel="next", <BASE/installation/repositories?per_page=100&page=2>; rel="last"`
	f.routes["/installation/repositories?per_page=100&page=2"] = `{"total_count":2,"repositories":[{"id":200,"full_name":"acme/other"}]}`
	f.routes["/orgs/acme/members?per_page=100"] = `[{"id":1,"login":"alice"},{"id":2,"login":"bob"}]`
	f.routes["/users/alice/keys?per_page=100"] = `[{"id":5,"key":"` + alice + `"}]`
	f.routes["/users/bob/keys?per_page=100"] = `[]`
	f.routes["/repos/acme/Assets/collaborators?affiliation=all&per_page=100"] = `[
		{"id":1,"login":"alice","permissions":{"push":true,"pull":true}},
		{"id":3,"login":"carol","permissions":{"admin":true}}]`
	f.routes["/repos/acme/other/collaborators?affiliation=all&per_page=100"] = `[{"id":2,"login":"bob","permissions":{"pull":true}}]`
	f.routes["/repos/acme/Assets/keys?per_page=100"] = `[{"id":10,"key":"` + deploy + `","title":"ci","read_only":true}]`
	pusher, _ := deployKey(t)
	f.routes["/repos/acme/other/keys?per_page=100"] = `[{"id":11,"key":"` + pusher + `","title":"release","read_only":false}]`
	f.routes["/jwks"] = `{"keys":[]}`
	return aliceFP, deployFP
}

func TestFullSync(t *testing.T) {
	f := newFakeGitHub(t)
	aliceFP, deployFP := f.organisation(t)
	p := f.provider("naraen-lfs")
	if p.Name() != "github" {
		t.Errorf("name = %q", p.Name())
	}
	snap, err := p.FullSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m := snap.Meta(); m.Provider != "github" || !m.SyncedAt.Equal(syncNow) {
		t.Errorf("meta = %+v", m)
	}
	assets, ok := snap.RepoByPath("acme/assets")
	if !ok || assets.ID != "100" {
		t.Fatalf("acme/assets = %+v, %v", assets, ok)
	}
	if other, ok := snap.RepoByPath("acme/other"); !ok || other.ID != "200" {
		t.Errorf("second page repo = %+v, %v", other, ok)
	}
	if id, ok := snap.KeyOwner(aliceFP); !ok || id.ID != "gh-user-1" || id.Name != "alice" {
		t.Errorf("alice's key = %+v, %v", id, ok)
	}
	if id, ok := snap.KeyOwner(deployFP); !ok || id.ID != "gh-deploy-key-10" || id.Kind != datastore.KindDeployKey {
		t.Errorf("deploy key = %+v, %v", id, ok)
	}
	for _, tt := range []struct {
		id, repo string
		want     datastore.Level
	}{
		{"gh-user-1", "100", datastore.LevelWrite},
		{"gh-user-2", "200", datastore.LevelRead},
		{"gh-user-2", "100", datastore.LevelNone},
		{"gh-user-3", "100", datastore.LevelNone}, // outside collaborator
		{"gh-deploy-key-10", "100", datastore.LevelRead},
		{"gh-deploy-key-11", "200", datastore.LevelWrite},
		{"workload:100", "100", datastore.LevelRead},
		{"workload:200", "200", datastore.LevelRead},
		{"workload:100", "200", datastore.LevelNone},
	} {
		if got := snap.GrantLevel(tt.id, tt.repo); got != tt.want {
			t.Errorf("%s on %s = %v, want %v", tt.id, tt.repo, got, tt.want)
		}
	}
	trusts := snap.Trusts()
	if len(trusts) != 1 || trusts[0].Issuer != ActionsIssuer || trusts[0].Audience != "naraen-lfs" || trusts[0].RepoClaim != "repository_id" {
		t.Errorf("trusts = %+v", trusts)
	}
	// One installation token served the whole sync.
	if n := f.tokenCalls.Load(); n != 1 {
		t.Errorf("installation tokens minted = %d", n)
	}
}

// Without an audience no workload trust or identity is registered.
func TestFullSyncWithoutCI(t *testing.T) {
	f := newFakeGitHub(t)
	f.organisation(t)
	delete(f.routes, "/jwks")
	snap, err := f.provider("").FullSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Trusts()) != 0 || snap.GrantLevel("workload:100", "100") != datastore.LevelNone {
		t.Errorf("CI registered without an audience: %+v", snap.Trusts())
	}
}

// Any failure fails the whole sync.
func TestFullSyncFailures(t *testing.T) {
	for name, mutate := range map[string]func(f *fakeGitHub){
		"token refused":    func(f *fakeGitHub) { f.tokenStatus = http.StatusInternalServerError },
		"repos page fails": func(f *fakeGitHub) { f.status["/installation/repositories?per_page=100"] = http.StatusBadGateway },
		"repos not json":   func(f *fakeGitHub) { f.routes["/installation/repositories?per_page=100"] = `[` },
		"repo without id": func(f *fakeGitHub) {
			f.routes["/installation/repositories?per_page=100&page=2"] = `{"repositories":[{"full_name":"acme/x"}]}`
		},
		"members fail":          func(f *fakeGitHub) { delete(f.routes, "/orgs/acme/members?per_page=100") },
		"member keys fail":      func(f *fakeGitHub) { delete(f.routes, "/users/bob/keys?per_page=100") },
		"member keys not json":  func(f *fakeGitHub) { f.routes["/users/bob/keys?per_page=100"] = `{` },
		"member key garbage":    func(f *fakeGitHub) { f.routes["/users/bob/keys?per_page=100"] = `[{"key":"nope"}]` },
		"collaborators fail":    func(f *fakeGitHub) { delete(f.routes, "/repos/acme/other/collaborators?affiliation=all&per_page=100") },
		"deploy keys fail":      func(f *fakeGitHub) { delete(f.routes, "/repos/acme/other/keys?per_page=100") },
		"deploy keys not json":  func(f *fakeGitHub) { f.routes["/repos/acme/other/keys?per_page=100"] = `{` },
		"deploy key without id": func(f *fakeGitHub) { f.routes["/repos/acme/other/keys?per_page=100"] = `[{"key":"x"}]` },
		"deploy key garbage":    func(f *fakeGitHub) { f.routes["/repos/acme/other/keys?per_page=100"] = `[{"id":11,"key":"nope"}]` },
		"jwks fails":            func(f *fakeGitHub) { f.status["/jwks"] = http.StatusServiceUnavailable },
		"jwks too large":        func(f *fakeGitHub) { f.routes["/jwks"] = `{"keys":[],"pad":"` + strings.Repeat("x", maxJWKS) + `"}` },
		"jwks not json":         func(f *fakeGitHub) { f.routes["/jwks"] = `not json` },
		"next page elsewhere": func(f *fakeGitHub) {
			f.links["/installation/repositories?per_page=100"] = `<https://evil.example.com/steal>; rel="next"`
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGitHub(t)
			f.organisation(t)
			mutate(f)
			if snap, err := f.provider("naraen-lfs").FullSync(context.Background()); err == nil || snap != nil {
				t.Fatalf("sync succeeded: %v", snap)
			}
		})
	}
}

func TestFullSyncRequestErrors(t *testing.T) {
	f := newFakeGitHub(t)
	f.organisation(t)
	p := f.provider("naraen-lfs")
	p.JWKSURL = "://not a url"
	if _, err := p.FullSync(context.Background()); err == nil {
		t.Error("bad JWKS URL accepted")
	}
	p = f.provider("naraen-lfs")
	p.JWKSURL = "http://127.0.0.1:1/jwks"
	if _, err := p.FullSync(context.Background()); err == nil {
		t.Error("unreachable JWKS accepted")
	}
	p = f.provider("")
	p.Client.BaseURL = "://bad"
	if _, err := p.FullSync(context.Background()); err == nil {
		t.Error("bad API URL accepted")
	}
	p = f.provider("")
	p.Client.BaseURL = "http://127.0.0.1:1"
	if _, err := p.FullSync(context.Background()); err == nil {
		t.Error("unreachable API accepted")
	}
}

// A listing whose next link never ends is cut off.
func TestPagesBounded(t *testing.T) {
	f := newFakeGitHub(t)
	f.organisation(t)
	f.links["/orgs/acme/members?per_page=100"] = `<BASE/orgs/acme/members?per_page=100>; rel="next"`
	_, err := f.provider("").FullSync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("err = %v", err)
	}
}

func TestResponseTooLarge(t *testing.T) {
	f := newFakeGitHub(t)
	f.organisation(t)
	f.routes["/orgs/acme/members?per_page=100"] = `[` + strings.Repeat(" ", maxPage) + `]`
	if _, err := f.provider("").FullSync(context.Background()); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v", err)
	}
}

func TestNextLink(t *testing.T) {
	for header, want := range map[string]string{
		`<https://a/x?page=2>; rel="next", <https://a/x?page=9>; rel="last"`: "https://a/x?page=2",
		`<https://a/x?page=9>; rel="last", <https://a/x?page=2>; rel="next"`: "https://a/x?page=2",
		`<https://a/x?page=2>; foo=bar; rel="next"`:                          "https://a/x?page=2",
		`<https://a/x?page=1>; rel="prev"`:                                   "",
		`https://a/x; rel="next"`:                                            "",
		`<https://a/x; rel="next"`:                                           "",
		`<https://a/x>`:                                                      "",
		``:                                                                   "",
	} {
		if got := nextLink(header); got != want {
			t.Errorf("nextLink(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestAppAuthCachesToken(t *testing.T) {
	f := newFakeGitHub(t)
	now := syncNow
	auth := &AppAuth{BaseURL: f.URL, AppID: "12345", InstallationID: "99", Key: f.appKey, HTTP: f.Client(), Now: func() time.Time { return now }}
	for range 3 {
		if tok, err := auth.Token(context.Background()); err != nil || tok != "inst-token" {
			t.Fatalf("token = %q, %v", tok, err)
		}
	}
	if n := f.tokenCalls.Load(); n != 1 {
		t.Errorf("minted %d tokens, want 1", n)
	}
	// Within five minutes of expiry the token is renewed.
	now = syncNow.Add(56 * time.Minute)
	if _, err := auth.Token(context.Background()); err != nil || f.tokenCalls.Load() != 2 {
		t.Errorf("renewal: %v, calls %d", err, f.tokenCalls.Load())
	}
}

func TestAppAuthFailures(t *testing.T) {
	f := newFakeGitHub(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	base := func() *AppAuth {
		return &AppAuth{BaseURL: f.URL, AppID: "12345", InstallationID: "99", Key: f.appKey, HTTP: f.Client(), Now: func() time.Time { return syncNow }}
	}
	for name, mutate := range map[string]func(a *AppAuth){
		"wrong key":    func(a *AppAuth) { a.Key = other },
		"bad base url": func(a *AppAuth) { a.BaseURL = "://bad" },
		"unreachable":  func(a *AppAuth) { a.BaseURL = "http://127.0.0.1:1" },
		"unsignable key": func(a *AppAuth) {
			a.Key = &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(15), E: 3}, D: big.NewInt(3)}
		},
		"other installed": func(a *AppAuth) { a.InstallationID = "98" },
	} {
		a := base()
		mutate(a)
		if tok, err := a.Token(context.Background()); err == nil || tok != "" {
			t.Errorf("%s: token %q", name, tok)
		}
	}
	f.tokenStatus = http.StatusOK // the right body, but not 201 Created
	if _, err := base().Token(context.Background()); err == nil {
		t.Error("non-201 accepted")
	}
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":""}`))
	}))
	defer broken.Close()
	a := base()
	a.BaseURL = broken.URL
	if _, err := a.Token(context.Background()); err == nil {
		t.Error("empty token accepted")
	}
}

func TestParseAppKey(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})
	der8, _ := x509.MarshalPKCS8PrivateKey(rk)
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8})
	for name, in := range map[string][]byte{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		if k, err := ParseAppKey(in); err != nil || !k.Equal(rk) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	derEC, _ := x509.MarshalPKCS8PrivateKey(ek)
	for name, in := range map[string][]byte{
		"not pem": []byte("nope"),
		"garbage": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}),
		"ec key":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derEC}),
	} {
		if _, err := ParseAppKey(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A page and a key document exactly at their size caps are accepted.
func TestSizesAtLimits(t *testing.T) {
	f := newFakeGitHub(t)
	f.organisation(t)
	f.routes["/users/bob/keys?per_page=100"] = `[` + strings.Repeat(" ", maxPage-2) + `]`
	jwks := `{"keys":[],"pad":""}`
	f.routes["/jwks"] = strings.Replace(jwks, `""`, `"`+strings.Repeat("x", maxJWKS-len(jwks))+`"`, 1)
	if len(f.routes["/jwks"]) != maxJWKS {
		t.Fatalf("jwks is %d bytes", len(f.routes["/jwks"]))
	}
	if _, err := f.provider("naraen-lfs").FullSync(context.Background()); err != nil {
		t.Fatalf("sync with bodies at the limits: %v", err)
	}
}
