package github

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/telemetry"
)

func deployKey(t testing.TB) (authorized, fingerprint string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), ssh.FingerprintSHA256(k)
}

func TestNarrowing(t *testing.T) {
	key, fp := deployKey(t)
	for name, tt := range map[string]struct {
		event, body string
		want        datastore.Narrowing
	}{
		"member removed from org": {
			"organization", `{"action":"member_removed","membership":{"user":{"id":42,"login":"alice"}}}`,
			datastore.Narrowing{DeactivateIdentities: []string{"gh-user-42"}},
		},
		"collaborator removed": {
			"member", `{"action":"removed","member":{"id":42,"login":"alice"},"repository":{"id":7}}`,
			datastore.Narrowing{DropGrants: []datastore.GrantRef{{IdentityID: "gh-user-42", RepoID: "7"}}},
		},
		"deploy key deleted": {
			"deploy_key", `{"action":"deleted","key":{"id":1,"key":"` + key + `"},"repository":{"id":7}}`,
			datastore.Narrowing{RevokeKeys: []string{fp}},
		},
		"member added":       {"organization", `{"action":"member_added","membership":{"user":{"id":42}}}`, datastore.Narrowing{}},
		"collaborator added": {"member", `{"action":"added","member":{"id":42},"repository":{"id":7}}`, datastore.Narrowing{}},
		"deploy key created": {"deploy_key", `{"action":"created","key":{"key":"` + key + `"}}`, datastore.Narrowing{}},
		"team change":        {"membership", `{"action":"removed","member":{"id":42}}`, datastore.Narrowing{}},
		"ping":               {"ping", `{"zen":"Keep it logically awesome."}`, datastore.Narrowing{}},
	} {
		got, err := Narrowing(tt.event, []byte(tt.body))
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: %+v, %v; want %+v", name, got, err, tt.want)
		}
	}
	for name, tt := range map[string]struct{ event, body string }{
		"not json":            {"organization", `{`},
		"org removal, no id":  {"organization", `{"action":"member_removed","membership":{"user":{}}}`},
		"collab, no member":   {"member", `{"action":"removed","repository":{"id":7}}`},
		"collab, no repo":     {"member", `{"action":"removed","member":{"id":42}}`},
		"deploy key, garbage": {"deploy_key", `{"action":"deleted","key":{"key":"not a key"}}`},
	} {
		if _, err := Narrowing(tt.event, []byte(tt.body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type recorder struct{ got []datastore.Narrowing }

func (r *recorder) Narrow(n datastore.Narrowing) { r.got = append(r.got, n) }

func sign(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestWebhookHandler(t *testing.T) {
	secret := []byte("webhook secret")
	store := &recorder{}
	var logs bytes.Buffer
	h := &WebhookHandler{Secret: secret, Store: store, Log: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	spans := tracetest.NewSpanRecorder()
	tracer := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)).Tracer("test")
	// post delivers inside a request span, as the listener does, and leaves
	// that span's attributes in lastSpan.
	var lastSpan attribute.Set
	post := func(event string, body []byte, sig string) int {
		ctx, span := tracer.Start(context.Background(), "POST /webhooks/github")
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/webhooks/github", bytes.NewReader(body))
		r.Header.Set("X-GitHub-Event", event)
		r.Header.Set("X-GitHub-Delivery", "d-1")
		r.Header.Set("X-Hub-Signature-256", sig)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		span.End()
		ended := spans.Ended()
		lastSpan = attribute.NewSet(ended[len(ended)-1].Attributes()...)
		return w.Code
	}
	spanAttr := func(k string) string {
		v, _ := lastSpan.Value(attribute.Key(k))
		return v.AsString()
	}
	removal := []byte(`{"action":"member_removed","membership":{"user":{"id":42,"login":"alice"}}}`)
	if code := post("organization", removal, sign(secret, removal)); code != http.StatusAccepted {
		t.Fatalf("signed removal: %d", code)
	}
	if spanAttr(telemetry.AttrEvent) != "organization" || spanAttr(telemetry.AttrDelivery) != "d-1" || lastSpan.HasValue(telemetry.AttrReason) {
		t.Errorf("span = %v", lastSpan.ToSlice())
	}
	if len(store.got) != 1 || store.got[0].DeactivateIdentities[0] != "gh-user-42" {
		t.Fatalf("narrowed = %+v", store.got)
	}
	if !strings.Contains(logs.String(), `"msg":"webhook applied"`) || !strings.Contains(logs.String(), `"delivery":"d-1"`) {
		t.Errorf("log = %s", logs.String())
	}
	ping := []byte(`{"zen":"hi"}`)
	if code := post("ping", ping, sign(secret, ping)); code != http.StatusAccepted || len(store.got) != 1 {
		t.Errorf("ping: %d, narrowed %d", code, len(store.got))
	}
	// Each kind of removal on its own is applied.
	key, fp := deployKey(t)
	collab := []byte(`{"action":"removed","member":{"id":42},"repository":{"id":7}}`)
	deleted := []byte(`{"action":"deleted","key":{"key":"` + key + `"}}`)
	if code := post("member", collab, sign(secret, collab)); code != http.StatusAccepted {
		t.Errorf("collaborator removal: %d", code)
	}
	if code := post("deploy_key", deleted, sign(secret, deleted)); code != http.StatusAccepted {
		t.Errorf("deploy key deletion: %d", code)
	}
	if len(store.got) != 3 || len(store.got[1].DropGrants) != 1 || store.got[2].RevokeKeys[0] != fp {
		t.Fatalf("narrowed = %+v", store.got)
	}
	for name, tt := range map[string]struct {
		body   []byte
		sig    string
		want   int
		reason string
	}{
		"unsigned":       {removal, "", http.StatusUnauthorized, "bad_signature"},
		"wrong secret":   {removal, sign([]byte("other"), removal), http.StatusUnauthorized, "bad_signature"},
		"malformed":      {[]byte(`{`), sign(secret, []byte(`{`)), http.StatusBadRequest, "malformed"},
		"oversized body": {bytes.Repeat([]byte(" "), maxDelivery+1), "", http.StatusRequestEntityTooLarge, "too_large"},
	} {
		if code := post("organization", tt.body, tt.sig); code != tt.want || spanAttr(telemetry.AttrReason) != tt.reason {
			t.Errorf("%s: %d with span reason %q, want %d and %q", name, code, spanAttr(telemetry.AttrReason), tt.want, tt.reason)
		}
	}
	if len(store.got) != 3 {
		t.Errorf("a refused delivery narrowed access: %+v", store.got)
	}
}

func FuzzNarrowing(f *testing.F) {
	key, _ := deployKey(f)
	for _, s := range []string{
		`{"action":"member_removed","membership":{"user":{"id":42}}}`,
		`{"action":"removed","member":{"id":42},"repository":{"id":7}}`,
		`{"action":"deleted","key":{"key":"` + key + `"}}`,
	} {
		for _, event := range []string{"organization", "member", "deploy_key"} {
			f.Add(event, s)
		}
	}
	f.Fuzz(func(t *testing.T, event, body string) {
		n, err := Narrowing(event, []byte(body))
		if err != nil && !reflect.DeepEqual(n, datastore.Narrowing{}) {
			t.Fatalf("error with a narrowing: %+v", n)
		}
		for _, id := range n.DeactivateIdentities {
			if !strings.HasPrefix(id, "gh-user-") {
				t.Fatalf("deactivated %q", id)
			}
		}
	})
}
