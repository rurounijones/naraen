//go:build integration

package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rurounijones/naraen/internal/lfs"
)

// fakeGitHub serves the GitHub API as an App installation on org acme would
// see it: repos acme/assets (1) and acme/other (2), one member whose key is
// the matrix writer's, with push on acme/assets.
func fakeGitHub(t *testing.T, e *env) *httptest.Server {
	t.Helper()
	routes := map[string]string{
		"/installation/repositories?per_page=100":                       `{"repositories":[{"id":1,"full_name":"acme/assets"},{"id":2,"full_name":"acme/other"}]}`,
		"/orgs/acme/members?per_page=100":                               `[{"id":501,"login":"writer"}]`,
		"/users/writer/keys?per_page=100":                               `[{"id":9,"key":"` + e.pubs["writer"] + `"}]`,
		"/repos/acme/assets/collaborators?affiliation=all&per_page=100": `[{"id":501,"login":"writer","permissions":{"push":true,"pull":true}}]`,
		"/repos/acme/other/collaborators?affiliation=all&per_page=100":  `[]`,
		"/repos/acme/assets/keys?per_page=100":                          `[]`,
		"/repos/acme/other/keys?per_page=100":                           `[]`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/app/installations/99/access_tokens" {
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"token":"inst","expires_at":%q}`, time.Now().Add(time.Hour).Format(time.RFC3339))
			return
		}
		body, ok := routes[r.URL.RequestURI()]
		if !ok || r.Header.Get("Authorization") != "Bearer inst" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// With the GitHub provider instead of a snapshot file, the server builds its
// datastore from the API at startup: it becomes ready, the org member's
// GitHub key authenticates and can push, and a key GitHub does not list is
// refused.
func TestGitHubProviderEndToEnd(t *testing.T) {
	needSSH(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e := startServerWith(t, func(e *env, vars []string) []string {
		gh := fakeGitHub(t, e)
		out := make([]string, 0, len(vars)+5)
		for _, v := range vars {
			if !strings.HasPrefix(v, "NARAEN_SNAPSHOT_FILE=") {
				out = append(out, v)
			}
		}
		keyFile := writeFile(t, filepath.Join(e.dir, "app.pem"),
			pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
		return append(out, "NARAEN_GITHUB_ORG=acme", "NARAEN_GITHUB_APP_ID=12345", "NARAEN_GITHUB_INSTALLATION_ID=99",
			"NARAEN_GITHUB_APP_KEY_FILE="+keyFile, "NARAEN_GITHUB_API_URL="+gh.URL)
	})
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(e.logs.String(), "full sync applied") {
		if time.Now().After(deadline) {
			t.Fatalf("no sync applied:\n%s", e.logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	out, err := e.ssh(t, "writer", sourceFor(0), "git-lfs-authenticate acme/assets upload")
	if err != nil {
		t.Fatalf("org member's key: %v", err)
	}
	c := e.checkToken(t, out, "gh-user-501", lfs.Upload, "acme/assets")
	if c.Subject != "gh-user-501" {
		t.Errorf("subject = %q", c.Subject)
	}
	_, err = e.ssh(t, "reader", sourceFor(1), "git-lfs-authenticate acme/assets download")
	checkDenied(t, err)

	bare, _ := e.origin(t)
	dir := e.clone(t, bare, "provider-push")
	content := []byte("pushed through the provider's datastore " + e.publicURL + "\n")
	writeFile(t, filepath.Join(dir, "p.bin"), content)
	for _, args := range [][]string{{"add", "p.bin"}, {"commit", "-m", "p"}} {
		if out, err := e.git(t, "", "", dir, nil, args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if out, err := e.git(t, "writer", sourceFor(2), dir, nil, "lfs", "push", "origin", "main"); err != nil || !stored(t, e.bucket, "1", oidFor(content)) {
		t.Fatalf("push: %v\n%s", err, out)
	}
}
