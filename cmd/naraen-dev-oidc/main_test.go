package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/oidc"
)

func pkcs8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	return &issuer{url: "http://oidc:8080", key: newKey(t), now: time.Now, log: slog.New(slog.DiscardHandler)}
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil))
	return rec
}

func TestParseKey(t *testing.T) {
	k := newKey(t)
	got, err := ParseKey(pkcs8(t, k))
	if err != nil || !got.Equal(k) {
		t.Fatalf("P-256 key: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"no PEM":  []byte("not a key"),
		"bad DER": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"P-384":   pkcs8(t, p384),
		"RSA":     pkcs8(t, rsaKey),
	} {
		if _, err := ParseKey(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// A minted token passes naraen's own verification against a trust entry
// holding the issuer's JWKS, and names the repository asked for.
func TestTokenVerifiesAgainstTrust(t *testing.T) {
	iss := newIssuer(t)
	h := iss.handler()
	rec := get(t, h, "/token?audience=naraen-dev&repository_id=1&repository=example/repo")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}
	var out struct{ Value string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	jwks := get(t, h, "/.well-known/jwks")
	if jwks.Header().Get("Content-Type") != "application/json" {
		t.Errorf("jwks content type %q", jwks.Header().Get("Content-Type"))
	}
	payload, err := oidc.VerifySignature(out.Value, jwks.Body.String())
	if err != nil {
		t.Fatalf("signature: %v", err)
	}
	trust := datastore.WorkloadTrust{Issuer: iss.url, Audience: "naraen-dev", JWKS: jwks.Body.String(), RepoClaim: "repository_id", MaxLevel: datastore.LevelRead}
	repo, _, err := oidc.Check(payload, []datastore.WorkloadTrust{trust}, time.Now())
	if err != nil || repo != "1" {
		t.Fatalf("claims: %q, %v", repo, err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "repo:example/repo:ref:refs/heads/main" || claims["repository"] != "example/repo" {
		t.Errorf("claims = %v", claims)
	}
	if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat != tokenTTL.Seconds() {
		t.Errorf("lifetime %v s", exp-iat)
	}
	// Tokens expire: past their lifetime, the same token is refused.
	if _, _, err := oidc.Check(payload, []datastore.WorkloadTrust{trust}, time.Now().Add(tokenTTL+time.Second)); err == nil {
		t.Error("expired token accepted")
	}
}

func TestDiscovery(t *testing.T) {
	rec := get(t, newIssuer(t).handler(), "/.well-known/openid-configuration")
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != "http://oidc:8080" || doc["jwks_uri"] != "http://oidc:8080/.well-known/jwks" {
		t.Errorf("discovery = %v", doc)
	}
}

func TestTokenRefusals(t *testing.T) {
	h := newIssuer(t).handler()
	for _, q := range []string{"repository_id=1&repository=a/b", "audience=x&repository=a/b", "audience=x&repository_id=1"} {
		if rec := get(t, h, "/token?"+q); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
	if rec := get(t, h, "/other"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path: %d", rec.Code)
	}
}

// A key that cannot sign (its point is not on the curve) fails the request
// rather than minting anything.
func TestSignFailure(t *testing.T) {
	iss := newIssuer(t)
	//nolint:staticcheck // Only the deprecated raw fields can build a key that fails to sign.
	iss.key = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, D: big.NewInt(1)}
	if rec := get(t, iss.handler(), "/token?audience=x&repository_id=1&repository=a/b"); rec.Code != http.StatusInternalServerError {
		t.Errorf("status %d", rec.Code)
	}
}

func TestJWKSRejectsBadKey(t *testing.T) {
	// (1, 1) is not on the curve.
	//nolint:staticcheck // Only the deprecated raw fields can build a key that fails to encode.
	if _, err := JWKS(&ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}); err == nil {
		t.Error("invalid key encoded")
	}
}

// failingListener accepts nothing.
type failingListener struct{ net.Listener }

func (failingListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed") }

func TestRun(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "oidc.key")
	if err := os.WriteFile(keyFile, pkcs8(t, newKey(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	good := map[string]string{"NARAEN_DEV_OIDC_ISSUER": "http://oidc:8080", "NARAEN_DEV_OIDC_KEY_FILE": keyFile, "NARAEN_DEV_OIDC_ADDR": "127.0.0.1:0"}
	log := slog.New(slog.DiscardHandler)

	ctx, cancel := context.WithCancel(context.Background())
	addr := make(chan string, 1)
	listen := func(network, a string) (net.Listener, error) {
		ln, err := net.Listen(network, a)
		if err == nil {
			addr <- ln.Addr().String()
		}
		return ln, err
	}
	done := make(chan error, 1)
	go func() { done <- run(ctx, env(good), os.ReadFile, listen, log) }()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+<-addr+"/.well-known/jwks", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("jwks: %d", resp.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("shutdown: %v", err)
	}

	// The default address is used when none is set.
	var asked string
	refuse := func(_, a string) (net.Listener, error) { asked = a; return nil, errors.New("listen failed") }
	noAddr := map[string]string{"NARAEN_DEV_OIDC_ISSUER": "http://oidc:8080", "NARAEN_DEV_OIDC_KEY_FILE": keyFile}
	if err := run(context.Background(), env(noAddr), os.ReadFile, refuse, log); err == nil || asked != ":8080" {
		t.Errorf("listen failure: %v, address %q", err, asked)
	}
	broken := func(network, a string) (net.Listener, error) {
		ln, err := net.Listen(network, a)
		return failingListener{ln}, err
	}
	if err := run(context.Background(), env(good), os.ReadFile, broken, log); err == nil || !strings.Contains(err.Error(), "accept failed") {
		t.Errorf("serve failure: %v", err)
	}
	for name, m := range map[string]map[string]string{
		"no issuer": {"NARAEN_DEV_OIDC_KEY_FILE": keyFile},
		"no key":    {"NARAEN_DEV_OIDC_ISSUER": "http://oidc:8080", "NARAEN_DEV_OIDC_KEY_FILE": filepath.Join(t.TempDir(), "missing")},
	} {
		if err := run(context.Background(), env(m), os.ReadFile, net.Listen, log); err == nil {
			t.Errorf("%s: started", name)
		}
	}
	bad := func(string) ([]byte, error) { return []byte("not a key"), nil }
	if err := run(context.Background(), env(good), bad, net.Listen, log); err == nil {
		t.Error("bad key: started")
	}
}

func TestReport(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	if report(nil, log) != 0 || report(errors.New("x"), log) != 1 {
		t.Error("wrong exit codes")
	}
}

func TestMainExits(t *testing.T) {
	t.Setenv("NARAEN_DEV_OIDC_ISSUER", "")
	code := 0
	exit = func(c int) { code = c }
	t.Cleanup(func() { exit = os.Exit })
	main()
	if code != 1 {
		t.Errorf("exit code %d", code)
	}
}
