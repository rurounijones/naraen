package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/config"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/httpapi"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/sshd"
	"github.com/rurounijones/naraen/internal/telemetry"
	"github.com/rurounijones/naraen/internal/token"
)

// snapshotFile writes a minimal valid snapshot, so these tests do not depend
// on fixtures elsewhere in the tree.
func snapshotFile(t *testing.T) string {
	t.Helper()
	return write(t, "snapshot.json", []byte(`{
		"identities": [{"id": "alice", "kind": "person", "active": true}],
		"repos": [{"id": "1", "path": "example/repo"}],
		"grants": [{"identity_id": "alice", "repo_id": "1", "level": "write"}]
	}`))
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// devEnv runs with ephemeral key material on loopback ports.
func devEnv() map[string]string {
	return map[string]string{
		"NARAEN_DEV":        "true",
		"NARAEN_SSH_ADDR":   "127.0.0.1:0",
		"NARAEN_HTTPS_ADDR": "127.0.0.1:0",
	}
}

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// prodEnv runs with key material from files, as production does.
func prodEnv(t *testing.T) map[string]string {
	t.Helper()
	isolateAWS(t)
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPEM, err := ssh.MarshalPrivateKey(hostPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := httpapi.SelfSigned(rand.Reader, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"NARAEN_SSH_ADDR":          "127.0.0.1:0",
		"NARAEN_HTTPS_ADDR":        "127.0.0.1:0",
		"NARAEN_TOKEN_KEYS_FILE":   write(t, "keys", []byte("k1 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n")),
		"NARAEN_SSH_HOST_KEY_FILE": write(t, "host", pem.EncodeToMemory(hostPEM)),
		"NARAEN_TLS_CERT_FILE":     write(t, "cert", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})),
		"NARAEN_TLS_KEY_FILE":      write(t, "key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		"NARAEN_PUBLIC_URL":        "https://lfs.example.com",
		"NARAEN_OTLP_ENDPOINT":     otlpReceiver(t).URL,
		"NARAEN_S3_BUCKET":         "acme-lfs",
		"NARAEN_S3_ENDPOINT":       "http://127.0.0.1:1",
	}
}

// isolateAWS points the AWS SDK at empty config files and a fixed region, so a
// test never reads the developer's ~/.aws or asks EC2 instance metadata.
func isolateAWS(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_CONFIG_FILE", write(t, "aws-config", nil))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", write(t, "aws-credentials", nil))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// receiver counts OTLP pushes by path, so a test can tell that metrics and
// logs left the process.
type receiver struct {
	*httptest.Server
	mu     sync.Mutex
	pushes map[string]int
}

func (r *receiver) count(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pushes[path]
}

func otlpReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{pushes: map[string]int{}}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		r.mu.Lock()
		r.pushes[req.URL.Path]++
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	t.Cleanup(r.Close)
	return r
}

// syncBuffer lets the test read what the server logs while it runs.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestRunConfigError(t *testing.T) {
	if err := run(context.Background(), env(nil), rand.Reader, discard()); err == nil {
		t.Fatal("expected a config error")
	}
}

func TestRunSnapshotError(t *testing.T) {
	e := devEnv()
	e["NARAEN_SNAPSHOT_FILE"] = filepath.Join(t.TempDir(), "missing.json")
	if err := run(context.Background(), env(e), rand.Reader, discard()); err == nil {
		t.Fatal("expected a snapshot error")
	}
}

func TestRunHostKeyError(t *testing.T) {
	err := run(context.Background(), env(devEnv()), iotest.ErrReader(errors.New("no entropy")), discard())
	if err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunCertificateError(t *testing.T) {
	// The host key consumes 32 bytes; the certificate then runs dry.
	err := run(context.Background(), env(devEnv()), io.LimitReader(rand.Reader, 32), discard())
	if err == nil {
		t.Fatal("expected a certificate error")
	}
}

func TestRunKeyMaterialFileErrors(t *testing.T) {
	tests := map[string]func(map[string]string){
		"missing host key": func(e map[string]string) { e["NARAEN_SSH_HOST_KEY_FILE"] += ".missing" },
		"bad host key":     func(e map[string]string) { e["NARAEN_SSH_HOST_KEY_FILE"] = e["NARAEN_TLS_CERT_FILE"] },
		"bad tls pair":     func(e map[string]string) { e["NARAEN_TLS_KEY_FILE"] = e["NARAEN_TLS_CERT_FILE"] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			e := prodEnv(t)
			mutate(e)
			if err := run(context.Background(), env(e), rand.Reader, discard()); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestRunSSHListenError(t *testing.T) {
	e := devEnv()
	e["NARAEN_SSH_ADDR"] = "not-an-address"
	err := run(context.Background(), env(e), rand.Reader, discard())
	if err == nil || !strings.Contains(err.Error(), "ssh listen") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunHTTPSListenError(t *testing.T) {
	e := devEnv()
	e["NARAEN_HTTPS_ADDR"] = "not-an-address"
	if err := run(context.Background(), env(e), rand.Reader, discard()); err == nil {
		t.Fatal("expected an HTTPS listen error")
	}
}

// serveUntilCancelled starts run with e, waits until it listens, stops it and
// returns its logs.
func serveUntilCancelled(t *testing.T, e map[string]string, random io.Reader) string {
	t.Helper()
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, env(e), random, slog.New(slog.NewTextHandler(logs, nil)))
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logs.String(), "listening") {
		if time.Now().After(deadline) {
			t.Fatalf("server never started listening: %s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("clean shutdown returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
	return logs.String()
}

func TestRunServesUntilCancelled(t *testing.T) {
	e := devEnv()
	e["NARAEN_SNAPSHOT_FILE"] = snapshotFile(t)
	logs := serveUntilCancelled(t, e, rand.Reader)
	if !strings.Contains(logs, "development mode") {
		t.Errorf("dev mode not announced: %s", logs)
	}
	if !strings.Contains(logs, "no bucket configured") {
		t.Errorf("missing storage not announced: %s", logs)
	}
}

// With every piece of key material configured, no randomness is needed and no
// development warning is logged. Metrics and logs reach the configured
// endpoint at the latest when the server flushes them on shutdown, logs still
// reach the local log too, and a snapshot file used outside dev mode is
// called out.
func TestRunServesWithConfiguredKeyMaterial(t *testing.T) {
	e := prodEnv(t)
	otlp := otlpReceiver(t)
	e["NARAEN_OTLP_ENDPOINT"] = otlp.URL
	e["NARAEN_SNAPSHOT_FILE"] = snapshotFile(t)
	e["NARAEN_GITHUB_WEBHOOK_SECRET_FILE"] = write(t, "hook", []byte("a webhook secret of enough length"))
	logs := serveUntilCancelled(t, e, iotest.ErrReader(errors.New("must not be used")))
	if strings.Contains(logs, "development mode") {
		t.Errorf("production run logged dev mode: %s", logs)
	}
	if !strings.Contains(logs, "datastore loaded from a snapshot file") {
		t.Errorf("snapshot file outside dev mode not called out: %s", logs)
	}
	if m, l := otlp.count("/v1/metrics"), otlp.count("/v1/logs"); m == 0 || l == 0 {
		t.Errorf("exported %d metrics and %d logs pushes, want both", m, l)
	}
	if strings.Contains(logs, "not exported") {
		t.Errorf("export configured but reported missing: %s", logs)
	}
}

// Without an endpoint the server still serves, and says nothing is exported.
func TestRunWithoutExport(t *testing.T) {
	e := prodEnv(t)
	delete(e, "NARAEN_OTLP_ENDPOINT")
	if logs := serveUntilCancelled(t, e, rand.Reader); !strings.Contains(logs, "metrics and logs are not exported") {
		t.Errorf("missing export not reported: %s", logs)
	}
}

// An exporter that cannot be built stops the server at startup: it would
// otherwise run without the metrics its alerts depend on.
func TestRunTelemetryError(t *testing.T) {
	e := prodEnv(t)
	// A CA certificate for a cleartext endpoint is a contradiction the
	// exporter refuses.
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_CERTIFICATE", e["NARAEN_TLS_CERT_FILE"])
	if err := run(context.Background(), env(e), rand.Reader, discard()); err == nil || !strings.Contains(err.Error(), "telemetry") {
		t.Fatalf("err = %v", err)
	}
}

func TestFlushTelemetryReportsFailure(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusBadRequest)
	}))
	defer broken.Close()
	tel, err := telemetry.New(context.Background(), telemetry.Export{Endpoint: broken.URL})
	if err != nil {
		t.Fatal(err)
	}
	telemetry.NewRecorder(tel.Meter).TokenIssued(context.Background(), "upload", "1", "alice")
	var logs bytes.Buffer
	flushTelemetry(tel, slog.New(slog.NewTextHandler(&logs, nil)))
	if !strings.Contains(logs.String(), "telemetry flush failed") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestRealMainFailureAndSuccess(t *testing.T) {
	var stdout bytes.Buffer
	if code := realMain(env(nil), &stdout); code != 1 || !strings.Contains(stdout.String(), "fatal") {
		t.Fatalf("code = %d, stdout = %q", code, stdout.String())
	}
}

func TestMainExits(t *testing.T) {
	orig := exit
	defer func() { exit = orig }()
	got := -1
	exit = func(code int) { got = code }
	for _, k := range []string{"NARAEN_DEV", "NARAEN_TOKEN_KEYS_FILE", "NARAEN_SSH_HOST_KEY_FILE"} {
		t.Setenv(k, "")
	}
	main()
	if got != 1 {
		t.Fatalf("exit code = %d, want 1", got)
	}
}

func TestLoadSnapshot(t *testing.T) {
	store := datastore.NewStore(time.Hour, datastore.DefaultLimits)
	if err := loadSnapshot(store, snapshotFile(t), false); err != nil {
		t.Fatalf("valid snapshot: %v", err)
	}
	if !store.Ready() {
		t.Fatal("store not ready after loading a snapshot")
	}
	if err := loadSnapshot(store, filepath.Join(t.TempDir(), "nope.json"), true); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := loadSnapshot(store, write(t, "bad.json", []byte("{")), true); err == nil {
		t.Fatal("malformed snapshot accepted")
	}
}

func TestRunTokenKeyError(t *testing.T) {
	// Every byte zero: the host key and certificate accept it, but an
	// ephemeral token key of one repeated byte is refused.
	err := run(context.Background(), env(devEnv()), bytes.NewReader(make([]byte, 1<<16)), discard())
	if err == nil || !strings.Contains(err.Error(), "token key") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadTokenSigner(t *testing.T) {
	configured := []token.Key{{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdef")}}
	s, err := loadTokenSigner(config.Config{TokenKeys: configured, TokenTTL: time.Minute}, iotest.ErrReader(errors.New("must not be used")))
	if err != nil || s.TTL() != time.Minute {
		t.Fatalf("configured keys: %v, %v", s, err)
	}
	// A token minted by the configured key verifies with a signer built from
	// that key alone, so the configured key is the one minting.
	tok, _, _ := s.Mint("alice", "1", lfs.Download)
	only, err := token.NewSigner(configured, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := only.Verify(tok, "1", lfs.Download); err != nil {
		t.Errorf("token not minted by the configured key: %v", err)
	}

	dev, err := loadTokenSigner(config.Config{TokenTTL: time.Minute}, rand.Reader)
	if err != nil {
		t.Fatalf("ephemeral key: %v", err)
	}
	devTok, _, _ := dev.Mint("alice", "1", lfs.Download)
	if _, err := only.Verify(devTok, "1", lfs.Download); err == nil {
		t.Error("ephemeral signer minted with the configured key")
	}
	if _, err := loadTokenSigner(config.Config{TokenTTL: time.Minute}, iotest.ErrReader(errors.New("no entropy"))); err == nil {
		t.Error("ephemeral key without entropy accepted")
	}
	if _, err := loadTokenSigner(config.Config{TokenKeys: configured}, rand.Reader); err == nil {
		t.Error("zero TTL accepted")
	}
}

// TestDevSnapshotFixture holds the committed dev keys and the snapshot that
// compose loads together: each public key must authenticate as the identity
// it is named after, so the README's local walkthrough keeps working.
func TestDevSnapshotFixture(t *testing.T) {
	store := datastore.NewStore(time.Hour, datastore.DefaultLimits)
	devSnapshot := filepath.Join("..", "..", "test", "testdata", "snapshot.json")
	// The public dev keys are refused outside dev mode, and nothing is loaded.
	if err := loadSnapshot(store, devSnapshot, false); err == nil || !strings.Contains(err.Error(), "development key") {
		t.Fatalf("dev snapshot outside dev mode: %v", err)
	}
	if store.Ready() {
		t.Fatal("refused snapshot was loaded")
	}
	if err := loadSnapshot(store, devSnapshot, true); err != nil {
		t.Fatal(err)
	}
	var fingerprints []string
	a := authz.New(store)
	for name, ops := range map[string][]lfs.Operation{
		"writer": {lfs.Download, lfs.Upload},
		"reader": {lfs.Download},
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "test", "testdata", "devkeys", name+".pub"))
		if err != nil {
			t.Fatal(err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		fingerprints = append(fingerprints, ssh.FingerprintSHA256(pub))
		id, err := a.IdentityForKey(ssh.FingerprintSHA256(pub))
		if err != nil || id.ID != name {
			t.Fatalf("%s.pub authenticates as %q, %v", name, id.ID, err)
		}
		for _, op := range ops {
			if _, err := a.Authorize(id.ID, "example/repo", op); err != nil {
				t.Errorf("%s may not %s example/repo: %v", name, op, err)
			}
		}
	}
	if _, err := a.Authorize("reader", "example/repo", lfs.Upload); err == nil {
		t.Error("reader may upload")
	}
	// The refusal list must name exactly the committed keys.
	slices.Sort(fingerprints)
	want := slices.Sorted(slices.Values(devKeyFingerprints))
	if !slices.Equal(fingerprints, want) {
		t.Errorf("devKeyFingerprints = %v, key files hold %v", want, fingerprints)
	}
}

// TestDevOIDCTrust holds the dev issuer's committed key, the trust entry in
// the dev snapshot and devOIDCKeyX together, and proves that a snapshot
// trusting that key is refused outside dev mode even when it lists none of
// the dev SSH keys, while one trusting any other key is not.
func TestDevOIDCTrust(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "testdata", "devkeys", "oidc.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("oidc.key: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("oidc.key holds %T", k)
	}
	point, err := ec.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if x := base64.RawURLEncoding.EncodeToString(point[1:33]); x != devOIDCKeyX {
		t.Errorf("oidc.key has x %s, devOIDCKeyX is %s", x, devOIDCKeyX)
	}

	devSnapshot, err := os.ReadFile(filepath.Join("..", "..", "test", "testdata", "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var data datastore.Data
	if err := json.Unmarshal(devSnapshot, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Trusts) != 1 || !strings.Contains(data.Trusts[0].JWKS, devOIDCKeyX) {
		t.Fatalf("dev snapshot trusts = %+v", data.Trusts)
	}
	// Without the dev SSH keys, only the trust entry can trip the refusal.
	data.Keys = nil
	snapshotFile := func(d datastore.Data) string {
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return write(t, "snapshot.json", b)
	}
	trustsDev := snapshotFile(data)
	if err := loadSnapshot(datastore.NewStore(time.Hour, datastore.DefaultLimits), trustsDev, false); err == nil || !strings.Contains(err.Error(), "development OIDC key") {
		t.Errorf("dev OIDC trust outside dev mode: %v", err)
	}
	if err := loadSnapshot(datastore.NewStore(time.Hour, datastore.DefaultLimits), trustsDev, true); err != nil {
		t.Errorf("dev OIDC trust in dev mode: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := other.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "other",
		"x": base64.RawURLEncoding.EncodeToString(p[1:33]), "y": base64.RawURLEncoding.EncodeToString(p[33:]),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	data.Trusts[0].JWKS = string(jwks)
	if err := loadSnapshot(datastore.NewStore(time.Hour, datastore.DefaultLimits), snapshotFile(data), false); err != nil {
		t.Errorf("another issuer's key outside dev mode: %v", err)
	}
}

// TestDevWebhookSecret holds the committed dev webhook secret and
// devWebhookSecretSHA256 together, and proves that a server outside dev mode
// refuses to start with it, while dev mode and any other secret are served.
func TestDevWebhookSecret(t *testing.T) {
	path := filepath.Join("..", "..", "test", "testdata", "devkeys", "webhook.secret")
	cfg, err := config.Load(env(map[string]string{"NARAEN_DEV": "true", "NARAEN_GITHUB_WEBHOOK_SECRET_FILE": path}), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(cfg.WebhookSecret); hex.EncodeToString(sum[:]) != devWebhookSecretSHA256 {
		t.Errorf("webhook.secret has SHA-256 %x, devWebhookSecretSHA256 is %s", sum, devWebhookSecretSHA256)
	}
	store := datastore.NewStore(time.Hour, datastore.DefaultLimits)
	if h, err := webhookHandler(cfg, store, discard()); err != nil || h == nil {
		t.Errorf("dev secret in dev mode: %v, %v", h, err)
	}
	if h, err := webhookHandler(config.Config{}, store, discard()); err != nil || h != nil {
		t.Errorf("no secret: %v, %v", h, err)
	}
	if h, err := webhookHandler(config.Config{WebhookSecret: []byte("another secret of enough length")}, store, discard()); err != nil || h == nil {
		t.Errorf("another secret outside dev mode: %v, %v", h, err)
	}

	// Outside dev mode the server does not start with it.
	e := prodEnv(t)
	e["NARAEN_SNAPSHOT_FILE"] = snapshotFile(t)
	e["NARAEN_GITHUB_WEBHOOK_SECRET_FILE"] = path
	if err := run(context.Background(), env(e), rand.Reader, discard()); err == nil || !strings.Contains(err.Error(), "development secret") {
		t.Errorf("dev secret outside dev mode: %v", err)
	}
}

// TestDevServerIdentity holds the committed dev host key and TLS certificate
// that compose serves with: both load in dev mode, and both are refused
// otherwise, so a production server cannot be started with keys anyone can
// read. The certificate must also cover every name the README and DAST use.
func TestDevServerIdentity(t *testing.T) {
	dir := filepath.Join("..", "..", "test", "testdata", "devkeys")
	dev := config.Config{
		Dev:            true,
		SSHHostKeyFile: filepath.Join(dir, "ssh_host_ed25519_key"),
		TLSCertFile:    filepath.Join(dir, "tls.crt"),
		TLSKeyFile:     filepath.Join(dir, "tls.key"),
	}
	s, err := loadHostKey(dev, nil)
	if err != nil || s == nil {
		t.Fatalf("dev host key: %v", err)
	}
	if fp := ssh.FingerprintSHA256(s.PublicKey()); fp != devHostKeyFingerprint {
		t.Errorf("host key file holds %s, devHostKeyFingerprint is %s", fp, devHostKeyFingerprint)
	}
	c, err := loadCertificate(dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"localhost", "naraen", "127.0.0.1", "::1"} {
		if err := leaf.VerifyHostname(host); err != nil {
			t.Errorf("dev certificate: %v", err)
		}
	}

	prod := dev
	prod.Dev = false
	if _, err := loadHostKey(prod, nil); err == nil || !strings.Contains(err.Error(), "development host key") {
		t.Errorf("dev host key outside dev mode: %v", err)
	}
	if _, err := loadCertificate(prod, nil); err == nil || !strings.Contains(err.Error(), "development certificate") {
		t.Errorf("dev certificate outside dev mode: %v", err)
	}
}

func TestSSHLimits(t *testing.T) {
	if got := sshLimits(config.Config{}); got != sshd.DefaultLimits {
		t.Errorf("no overrides: %+v, want the defaults", got)
	}
	got := sshLimits(config.Config{SSHConnBurst: 100, SSHConnInterval: time.Millisecond})
	want := sshd.DefaultLimits
	want.ConnBurst, want.ConnInterval = 100, time.Millisecond
	if got != want {
		t.Errorf("overrides: %+v, want %+v", got, want)
	}
}

func TestLoadStorage(t *testing.T) {
	isolateAWS(t)
	if s, err := loadStorage(context.Background(), "http://127.0.0.1:8333", "acme-lfs"); err != nil || s == nil {
		t.Fatalf("storage: %v, %v", s, err)
	}
	t.Setenv("AWS_REGION", "")
	if _, err := loadStorage(context.Background(), "", "acme-lfs"); err == nil || !strings.Contains(err.Error(), "AWS_REGION") {
		t.Errorf("no region: %v", err)
	}
	// A setting the SDK cannot parse stops startup.
	t.Setenv("AWS_MAX_ATTEMPTS", "many")
	if _, err := loadStorage(context.Background(), "", "acme-lfs"); err == nil {
		t.Error("unparseable AWS setting accepted")
	}
}

// A production server whose storage cannot be set up does not start.
func TestRunStorageError(t *testing.T) {
	e := prodEnv(t)
	t.Setenv("AWS_REGION", "")
	if err := run(context.Background(), env(e), rand.Reader, discard()); err == nil || !strings.Contains(err.Error(), "s3") {
		t.Fatalf("err = %v", err)
	}
}

func appKeyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

func TestGitHubProvider(t *testing.T) {
	g := config.GitHub{
		Org: "acme", AppID: "1", InstallationID: "2", AppKey: appKeyPEM(t),
		APIURL: "https://api.github.com", JWKSURL: "https://keys", Audience: "aud",
	}
	rec := telemetry.NewRecorder(noop.NewMeterProvider())
	log := slog.New(slog.DiscardHandler)
	p, err := githubProvider(g, rec, log)
	if err != nil || p.Org != "acme" || p.Audience != "aud" || p.JWKSURL != "https://keys" || p.Client.BaseURL != g.APIURL || p.Client.Rec != rec {
		t.Fatalf("provider = %+v, %v", p, err)
	}
	g.AppKey = []byte("not a key")
	if _, err := githubProvider(g, rec, log); err == nil {
		t.Error("bad app key accepted")
	}
}

// A server configured with the GitHub provider starts and syncs in the
// background; GitHub being unreachable fails the sync, not the server.
func TestRunWithGitHubProvider(t *testing.T) {
	e := prodEnv(t)
	e["NARAEN_GITHUB_ORG"] = "acme"
	e["NARAEN_GITHUB_APP_ID"] = "1"
	e["NARAEN_GITHUB_INSTALLATION_ID"] = "2"
	e["NARAEN_GITHUB_APP_KEY_FILE"] = write(t, "app.pem", appKeyPEM(t))
	e["NARAEN_GITHUB_API_URL"] = "http://127.0.0.1:1"
	logs := serveUntilCancelled(t, e, rand.Reader)
	if !strings.Contains(logs, "full sync failed") {
		t.Errorf("sync failure not logged: %s", logs)
	}
	e["NARAEN_GITHUB_APP_KEY_FILE"] = write(t, "bad.pem", []byte("nope"))
	if err := run(context.Background(), env(e), rand.Reader, discard()); err == nil {
		t.Error("server started with an unparseable app key")
	}
}
