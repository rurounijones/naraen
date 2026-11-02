//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/storage"
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

	// Webhooks apply removals at once, without waiting for the next full
	// sync. Removing the collaborator drops the grant: the key still signs
	// in, but the request is refused.
	signed := func(event string, body []byte) int {
		m := hmac.New(sha256.New, []byte(webhookSecret))
		m.Write(body)
		return e.deliverEvent(t, event, body, "sha256="+hex.EncodeToString(m.Sum(nil)))
	}
	if code := signed("member", []byte(`{"action":"removed","member":{"id":501,"login":"writer"},"repository":{"id":1}}`)); code != http.StatusAccepted {
		t.Fatalf("member removed delivery: %d", code)
	}
	_, err = e.ssh(t, "writer", sourceFor(3), "git-lfs-authenticate acme/assets download")
	if err == nil || !strings.Contains(err.Error(), requestRefused) {
		t.Fatalf("after collaborator removal: %v", err)
	}
	// Removing the member from the org deactivates them: the key itself
	// is refused.
	if code := signed("organization", []byte(`{"action":"member_removed","membership":{"user":{"id":501,"login":"writer"}}}`)); code != http.StatusAccepted {
		t.Fatalf("member_removed delivery: %d", code)
	}
	_, err = e.ssh(t, "writer", sourceFor(4), "git-lfs-authenticate acme/assets download")
	if err == nil || !strings.Contains(err.Error(), keyRefused) {
		t.Fatalf("after org removal: %v", err)
	}

	// The sync is a trace holding each request it made to GitHub, the
	// installation token's included, and each webhook delivery is a request
	// span naming its event.
	e.stop()
	spans := e.otlp.spans()
	syncs := find(spans, "provider full sync", map[string]string{"lfs.provider": "github"})
	if len(syncs) == 0 || syncs[0].failed {
		t.Fatalf("no successful sync span (spans: %v)", spans)
	}
	requests := map[string]int{}
	for _, s := range spans {
		if s.parent == syncs[0].id && s.trace == syncs[0].trace {
			requests[s.name]++
		}
	}
	if requests["HTTP POST"] != 1 || requests["HTTP GET"] < 7 {
		t.Errorf("requests inside the sync = %v, want the token's POST and at least the 7 listings", requests)
	}
	for _, event := range []string{"member", "organization"} {
		if len(find(spans, "POST /webhooks/github", map[string]string{"lfs.event": event, "http.response.status_code": "202"})) != 1 {
			t.Errorf("no span for the %s delivery", event)
		}
	}
}

// awaitLog waits for the current server process to log want.
func (e *env) awaitLog(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(e.logs.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("%q never logged:\n%s", want, e.logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A replacement server keeps working while GitHub is down, from the signed copy
// of the datastore its predecessor left at the bucket's root. It refuses a copy
// that has been altered, and access a webhook removed stays removed.
func TestSnapshotSurvivesRestart(t *testing.T) {
	needSSH(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var gh *httptest.Server
	e := startServerWith(t, func(e *env, vars []string) []string {
		gh = fakeGitHub(t, e)
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
	e.awaitLog(t, "datastore snapshot saved")
	authenticate := func(src int) error {
		_, err := e.ssh(t, "writer", sourceFor(src), "git-lfs-authenticate acme/assets download")
		return err
	}
	if err := authenticate(0); err != nil {
		t.Fatalf("before restart: %v", err)
	}
	ctx := context.Background()
	got, err := s3Admin().GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(e.bucket), Key: aws.String(storage.SnapshotKey)})
	if err != nil {
		t.Fatalf("no copy at the bucket's root: %v", err)
	}
	var good bytes.Buffer
	if _, err := good.ReadFrom(got.Body); err != nil {
		t.Fatal(err)
	}
	put := func(body []byte) {
		t.Helper()
		if _, err := s3Admin().PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(e.bucket), Key: aws.String(storage.SnapshotKey), Body: bytes.NewReader(body)}); err != nil {
			t.Fatal(err)
		}
	}

	gh.Close()

	// An altered copy is refused, so the server stays not-ready.
	altered := good.Bytes()
	altered = bytes.Replace(bytes.Clone(altered), []byte(`"payload":"`), []byte(`"payload":"AAAA`), 1)
	put(altered)
	e.restart()
	e.awaitLog(t, "saved datastore snapshot refused")
	if err := authenticate(1); err == nil {
		t.Error("altered copy was served")
	}

	// The genuine copy serves, with GitHub still down.
	put(good.Bytes())
	e.restart()
	e.awaitLog(t, "datastore restored from saved snapshot")
	e.awaitLog(t, "full sync failed")
	if err := authenticate(2); err != nil {
		t.Fatalf("after restart with GitHub down: %v", err)
	}

	// A removal made while running reaches the copy, so it survives the next
	// restart too.
	body := []byte(`{"action":"member_removed","membership":{"user":{"id":501,"login":"writer"}}}`)
	m := hmac.New(sha256.New, []byte(webhookSecret))
	m.Write(body)
	if code := e.deliverEvent(t, "organization", body, "sha256="+hex.EncodeToString(m.Sum(nil))); code != http.StatusAccepted {
		t.Fatalf("delivery: %d", code)
	}
	e.awaitLog(t, "datastore snapshot saved")
	e.restart()
	e.awaitLog(t, "datastore restored from saved snapshot")
	if err := authenticate(3); err == nil || !strings.Contains(err.Error(), keyRefused) {
		t.Errorf("removed member after restart: %v", err)
	}
}
