//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/oidc"
)

const (
	ciIssuerURL = "https://ci.example.test"
	ciAudience  = "naraen-lfs"
)

// ciIssuer stands in for GitHub Actions' OIDC issuer: an ES256 key whose
// public half the snapshot trusts, as the GitHub provider would register it.
type ciIssuer struct{ key *ecdsa.PrivateKey }

var b64 = base64.RawURLEncoding

// addCI registers the issuer in data and gives each repo its workload
// identity with a read grant, the convention oidc.WorkloadPrefix documents.
func addCI(t *testing.T, data *datastore.Data) *ciIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Bytes is the uncompressed point: 0x04, then x and y.
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "ci-1",
		"x": b64.EncodeToString(point[1:33]), "y": b64.EncodeToString(point[33:]),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	data.Trusts = append(data.Trusts, datastore.WorkloadTrust{
		Issuer: ciIssuerURL, Audience: ciAudience, JWKS: string(jwks), RepoClaim: "repository_id", MaxLevel: datastore.LevelRead,
	})
	for _, repo := range []string{"1", "2"} {
		id := oidc.WorkloadPrefix + repo
		data.Identities = append(data.Identities, datastore.Identity{ID: id, Kind: datastore.KindWorkload, Name: id, Active: true})
		data.Grants = append(data.Grants, datastore.Grant{IdentityID: id, RepoID: repo, Level: datastore.LevelRead})
	}
	return &ciIssuer{key: key}
}

// token returns an OIDC token for repoID signed with key.
func (c *ciIssuer) token(t *testing.T, key *ecdsa.PrivateKey, repoID string) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "ci-1", "typ": "JWT"})
	p, _ := json.Marshal(map[string]any{
		"iss": ciIssuerURL, "aud": ciAudience, "repository_id": repoID,
		"sub": "repo:acme/assets:ref:refs/heads/main", "exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

// exchange posts an OIDC token to the repo's exchange endpoint and returns
// the status and, on success, the LFS Authorization header.
func (e *env) exchange(t *testing.T, path, oidcToken string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, e.publicURL+"/"+path+"/ci/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+oidcToken)
	resp, err := e.httpClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Header map[string]string `json:"header"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.Header["Authorization"]
}

// TestCIMatrix runs the CI rows of the design's matrix: a workload with an
// OIDC token from a trusted issuer exchanges it for a read-only token and
// pulls with git-lfs over HTTPS, with no SSH key and no GitHub seat. It
// cannot push, cannot use another repo's token, and a token signed by any
// other key is refused.
func TestCIMatrix(t *testing.T) {
	e := startServer(t)
	bare, seed := e.origin(t)
	status, header := e.exchange(t, "acme/assets", e.ci.token(t, e.ci.key, "1"))
	if status != http.StatusOK || header == "" {
		t.Fatalf("exchange for its own repo: %d", status)
	}
	https := []string{"-c", "lfs.url=" + e.publicURL + "/acme/assets", "-c", "http.extraHeader=Authorization: " + header}

	t.Run("download", func(t *testing.T) {
		dir := e.clone(t, bare, "ci-download")
		out, err := e.git(t, "", "", dir, nil, append(https, "lfs", "pull")...)
		got, _ := os.ReadFile(filepath.Join(dir, "seed.bin"))
		if err != nil || !bytes.Equal(got, seed) {
			t.Fatalf("CI download failed: %v\n%s", err, out)
		}
	})
	t.Run("upload", func(t *testing.T) {
		dir := e.clone(t, bare, "ci-upload")
		content := []byte("pushed by CI " + e.publicURL + "\n")
		writeFile(t, filepath.Join(dir, "ci.bin"), content)
		for _, args := range [][]string{{"add", "ci.bin"}, {"commit", "-m", "ci"}} {
			if out, err := e.git(t, "", "", dir, nil, args...); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
		out, err := e.git(t, "", "", dir, nil, append(https, "lfs", "push", "origin", "main")...)
		if err == nil || stored(t, e.bucket, "1", oidFor(content)) {
			t.Fatalf("CI upload must be denied\n%s", out)
		}
	})
	t.Run("another repo's token", func(t *testing.T) {
		if status, _ := e.exchange(t, "acme/assets", e.ci.token(t, e.ci.key, "2")); status != http.StatusForbidden {
			t.Errorf("status %d, want 403", status)
		}
	})
	t.Run("forged token", func(t *testing.T) {
		forger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if status, _ := e.exchange(t, "acme/assets", e.ci.token(t, forger, "1")); status != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", status)
		}
	})
}
