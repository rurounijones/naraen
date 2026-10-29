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
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/config"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/httpapi"
	"github.com/rurounijones/naraen/internal/sshd"
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
// development warning is logged.
func TestRunServesWithConfiguredKeyMaterial(t *testing.T) {
	logs := serveUntilCancelled(t, prodEnv(t), iotest.ErrReader(errors.New("must not be used")))
	if strings.Contains(logs, "development mode") {
		t.Errorf("production run logged dev mode: %s", logs)
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
	if err := loadSnapshot(store, snapshotFile(t)); err != nil {
		t.Fatalf("valid snapshot: %v", err)
	}
	if !store.Ready() {
		t.Fatal("store not ready after loading a snapshot")
	}
	if err := loadSnapshot(store, filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := loadSnapshot(store, write(t, "bad.json", []byte("{"))); err == nil {
		t.Fatal("malformed snapshot accepted")
	}
}

func TestRefuseAll(t *testing.T) {
	out, err := refuseAll{}.Handle(context.Background(), "id", sshd.Command{})
	if err == nil || out != nil {
		t.Fatalf("out = %v, err = %v", out, err)
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
