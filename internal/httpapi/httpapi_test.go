package httpapi

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/iotest"
	"time"
)

type fakeReady bool

func (f fakeReady) Ready() bool { return bool(f) }

// teapot stands in for the Batch handler, so a test can tell it was reached.
var teapot = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })

// accepted stands in for the token exchange in the same way.
var accepted = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })

// created stands in for the webhook.
var created = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })

// Without a webhook handler the route does not exist.
func TestWebhookUnmounted(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler(fakeReady(true), teapot, accepted, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhooks/github", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestEndpoints(t *testing.T) {
	tests := []struct {
		name   string
		ready  bool
		method string
		path   string
		want   int
	}{
		{"healthz ok when not ready", false, "GET", "/healthz", http.StatusOK},
		{"readyz ready", true, "GET", "/readyz", http.StatusOK},
		{"readyz not ready", false, "GET", "/readyz", http.StatusServiceUnavailable},
		{"unknown path", true, "GET", "/nope", http.StatusNotFound},
		{"wrong method", true, "POST", "/healthz", http.StatusMethodNotAllowed},
		{"batch", true, "POST", "/acme/assets/objects/batch", http.StatusTeapot},
		{"batch by GET", true, "GET", "/acme/assets/objects/batch", http.StatusMethodNotAllowed},
		{"batch too deep", true, "POST", "/acme/x/assets/objects/batch", http.StatusNotFound},
		{"ci token", true, "POST", "/acme/assets/ci/token", http.StatusAccepted},
		{"ci token by GET", true, "GET", "/acme/assets/ci/token", http.StatusMethodNotAllowed},
		{"webhook", true, "POST", "/webhooks/github", http.StatusCreated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			Handler(fakeReady(tt.ready), teapot, accepted, created).ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			for _, h := range []string{"Strict-Transport-Security", "X-Content-Type-Options", "Cache-Control", "Content-Security-Policy", "Cross-Origin-Resource-Policy"} {
				if rec.Header().Get(h) == "" {
					t.Errorf("missing security header %s", h)
				}
			}
		})
	}
}

func TestNewServerTimeouts(t *testing.T) {
	s := NewServer(":0", http.NotFoundHandler(), nil)
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 || s.MaxHeaderBytes == 0 {
		t.Errorf("server missing limits: %+v", s)
	}
}

func TestTLS13Only(t *testing.T) {
	cert, err := SelfSigned(rand.Reader, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(Handler(fakeReady(true), teapot, accepted, created))
	srv.TLS = TLSConfig(cert)
	srv.StartTLS()
	defer srv.Close()

	dial := func(max uint16) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         max,
		}}}
		resp, err := c.Get(srv.URL + "/healthz")
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := dial(tls.VersionTLS13); err != nil {
		t.Errorf("TLS 1.3 failed: %v", err)
	}
	if err := dial(tls.VersionTLS12); err == nil {
		t.Error("TLS 1.2 was accepted")
	}
}

func TestSelfSignedValidity(t *testing.T) {
	cert, err := SelfSigned(rand.Reader, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if d := now.Sub(leaf.NotBefore); d < 0 || d > 5*time.Minute {
		t.Errorf("NotBefore is %v before now, want a small positive skew allowance", d)
	}
	if d := leaf.NotAfter.Sub(now); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("NotAfter is %v from now, want about 24h", d)
	}
}

func TestSelfSignedFailures(t *testing.T) {
	tests := map[string]struct {
		random io.Reader
		hosts  []string
	}{
		"key generation": {iotest.ErrReader(errors.New("no entropy")), []string{"localhost"}},
		// Ed25519 consumes 32 bytes; the serial number then hits EOF.
		"serial number": {io.LimitReader(rand.Reader, 32), []string{"localhost"}},
		// DNS names must be ASCII, so signing fails.
		"certificate": {rand.Reader, []string{"löcalhost"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := SelfSigned(tt.random, tt.hosts...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
