package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/config"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/httpapi"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/sshd"
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
	}
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
	if logs := serveUntilCancelled(t, e, rand.Reader); !strings.Contains(logs, "development mode") {
		t.Errorf("dev mode not announced: %s", logs)
	}
}

// With every piece of key material configured, no randomness is needed and no
// development warning is logged, and a snapshot file used outside dev mode is
// called out.
func TestRunServesWithConfiguredKeyMaterial(t *testing.T) {
	e := prodEnv(t)
	e["NARAEN_SNAPSHOT_FILE"] = snapshotFile(t)
	logs := serveUntilCancelled(t, e, iotest.ErrReader(errors.New("must not be used")))
	if strings.Contains(logs, "development mode") {
		t.Errorf("production run logged dev mode: %s", logs)
	}
	if !strings.Contains(logs, "datastore loaded from a snapshot file") {
		t.Errorf("snapshot file outside dev mode not called out: %s", logs)
	}
}

func TestRealMainFailureAndSuccess(t *testing.T) {
	var stderr bytes.Buffer
	if code := realMain(env(nil), &stderr); code != 1 || !strings.Contains(stderr.String(), "fatal") {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
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
	tok, _ := s.Mint("alice", "1", lfs.Download)
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
	devTok, _ := dev.Mint("alice", "1", lfs.Download)
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
