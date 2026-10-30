//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
)

// webhookSecret is the test server's GitHub webhook secret.
const webhookSecret = "integration-webhook-secret" // #nosec G101 -- test-only value

// A signed deploy_key deleted delivery revokes that key at once: the next
// SSH sign-in with it is refused, without waiting for a full sync. An
// unsigned delivery changes nothing.
func TestWebhookRevokesDeployKey(t *testing.T) {
	needSSH(t)
	e := startServer(t)
	as, src := "deploy-key-write", sourceFor(0)
	if _, err := e.ssh(t, as, src, "git-lfs-authenticate acme/assets download"); err != nil {
		t.Fatalf("before revocation: %v", err)
	}
	body := []byte(`{"action":"deleted","key":{"id":1,"key":"` + e.pubs[as] + `"},"repository":{"id":1}}`)
	if code := e.deliver(t, body, "sha256=00"); code != http.StatusUnauthorized {
		t.Fatalf("unsigned delivery: %d", code)
	}
	if _, err := e.ssh(t, as, src, "git-lfs-authenticate acme/assets download"); err != nil {
		t.Fatalf("an unsigned delivery revoked the key: %v", err)
	}
	m := hmac.New(sha256.New, []byte(webhookSecret))
	m.Write(body)
	if code := e.deliver(t, body, "sha256="+hex.EncodeToString(m.Sum(nil))); code != http.StatusAccepted {
		t.Fatalf("signed delivery: %d", code)
	}
	_, err := e.ssh(t, as, src, "git-lfs-authenticate acme/assets download")
	checkDenied(t, err)
}

func (e *env) deliver(t *testing.T, body []byte, sig string) int {
	t.Helper()
	return e.deliverEvent(t, "deploy_key", body, sig)
}

// deliverEvent posts a webhook delivery of the named event to the server.
func (e *env) deliverEvent(t *testing.T, event string, body []byte, sig string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, e.publicURL+"/webhooks/github", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", "test-delivery")
	req.Header.Set("X-Hub-Signature-256", sig)
	resp, err := e.httpClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
