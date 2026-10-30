// Package attack holds regression tests for known attacks against the server.
package attack

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/sshd"
	"github.com/rurounijones/naraen/internal/telemetry"
)

// CVE-2024-45337: x/crypto may invoke PublicKeyCallback for keys a client
// offers but never proves it holds, so a server that takes identity from a
// callback invocation, rather than from the Permissions of the key that
// actually authenticated, can be made to treat one user as another.
//
// What these tests can and cannot show. The CVE's full sequence, in which the
// callback accepts a victim's key and the attacker then authenticates with
// another key on the same connection, cannot be driven from the x/crypto
// client against x/crypto v0.31.0 or later: the client always signs once a
// key is accepted, and the server drops the connection on a bad signature.
// The library's own guarantee (it caches one key, so the callback's last call
// is the authenticating key) is held in place by TestXCryptoVersionFloor, and
// the server's half (identity only from the returned Permissions) by
// sshd.TestKeyCallbackCarriesIdentityOfAuthenticatingKey. What is checked end
// to end here is that a key the callback accepts, presented with a signature
// its holder did not make, never authenticates.

func signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// notHeld presents a public key and answers with a well-formed but invalid
// signature, as a client that has a victim's public key but not its private
// half would. Returning an error instead would make the x/crypto client abort
// the handshake before any signature reached the server, which proves nothing.
type notHeld struct{ pub ssh.PublicKey }

func (n notHeld) PublicKey() ssh.PublicKey { return n.pub }
func (n notHeld) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return &ssh.Signature{Format: n.pub.Type(), Blob: make([]byte, ed25519.SignatureSize)}, nil
}

// fixture is a server whose datastore knows a victim and an attacker, both
// active, and which records every identity its key callback accepts.
type fixture struct {
	victim, attacker, host ssh.Signer
	addr                   string

	mu       sync.Mutex
	accepted []string // identities the key callback accepted, in order
}

// name returns which fixture identity owns k.
func (f *fixture) name(k ssh.PublicKey) string {
	switch ssh.FingerprintSHA256(k) {
	case ssh.FingerprintSHA256(f.victim.PublicKey()):
		return "victim"
	case ssh.FingerprintSHA256(f.attacker.PublicKey()):
		return "attacker"
	default:
		return "unknown"
	}
}

func (f *fixture) acceptedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.accepted...)
}

// identityHandler answers every command with the identity the server passed
// to it, which is the identity a real handler would act as.
type identityHandler struct{}

func (identityHandler) Handle(_ context.Context, s sshd.Session, _ sshd.Command) ([]byte, error) {
	return []byte(s.IdentityID), nil
}

var reportIdentity sshd.Handler = identityHandler{}

func start(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{victim: signer(t), attacker: signer(t), host: signer(t)}
	person := func(id string) datastore.Identity {
		return datastore.Identity{ID: id, Kind: datastore.KindPerson, Active: true}
	}
	snap, err := datastore.NewSnapshot(datastore.Data{
		Identities: []datastore.Identity{person("victim"), person("attacker")},
		Keys: []datastore.Key{
			{Fingerprint: ssh.FingerprintSHA256(f.victim.PublicKey()), IdentityID: "victim"},
			{Fingerprint: ssh.FingerprintSHA256(f.attacker.PublicKey()), IdentityID: "attacker"},
		},
		Repos: []datastore.Repo{{ID: "r1", Path: "acme/assets"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	st := datastore.NewStore(time.Hour, datastore.DefaultLimits)
	if err := st.Swap(st.StartSync(), snap); err != nil {
		t.Fatal(err)
	}
	cfg := sshd.NewServerConfig(f.host, authz.New(st))
	inner := cfg.PublicKeyCallback
	cfg.PublicKeyCallback = func(m ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		p, err := inner(m, k)
		if err == nil {
			f.mu.Lock()
			f.accepted = append(f.accepted, f.name(k))
			f.mu.Unlock()
		}
		return p, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = sshd.Serve(ctx, ln, cfg, sshd.DefaultLimits, reportIdentity, telemetry.NewRecorder(noop.NewMeterProvider()), slog.New(slog.DiscardHandler))
	}()
	t.Cleanup(func() { cancel(); <-done })
	return f
}

// dial authenticates with signers, offered in order, and returns the identity
// the handler reports, or "" if authentication fails.
func (f *fixture) dial(t *testing.T, signers ...ssh.Signer) string {
	t.Helper()
	c, err := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.FixedHostKey(f.host.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return ""
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out, err := sess.Output("git-lfs-authenticate acme/assets download")
	if err != nil {
		t.Fatalf("authenticated session failed: %v", err)
	}
	return string(out)
}

// A key that is offered, accepted by the callback and then signed for without
// the private key must not authenticate, while its real holder can.
func TestCVE202445337OfferedKeyWithoutPrivateHalfFails(t *testing.T) {
	f := start(t)
	if id := f.dial(t, notHeld{f.victim.PublicKey()}); id != "" {
		t.Fatalf("victim's key without its private half authenticated as %q", id)
	}
	// The forged attempt must have got as far as the callback accepting the
	// key, or the rejection proves nothing about signature checking.
	if got := f.acceptedIDs(); len(got) != 1 || got[0] != "victim" {
		t.Fatalf("callback accepted %v, want exactly the victim's key", got)
	}
	// The same key with its private half works, so the rejection above was
	// the signature and not the fixture.
	if id := f.dial(t, f.victim); id != "victim" {
		t.Fatalf("victim's own key authenticated as %q", id)
	}
	// An attacker holding a key of their own is still only themselves after
	// the victim's key was offered on an earlier connection.
	if id := f.dial(t, f.attacker); id != "attacker" {
		t.Fatalf("attacker's own key authenticated as %q", id)
	}
}

// TestXCryptoVersionFloor fails if the golang.org/x/crypto linked into this
// test binary is older than the release that fixed CVE-2024-45337 (v0.31.0).
// The version comes from the binary's own build info, so the check needs no
// go command and cannot be skipped.
func TestXCryptoVersionFloor(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build info in the test binary")
	}
	v := ""
	for _, dep := range info.Deps {
		if dep.Path != "golang.org/x/crypto" {
			continue
		}
		v = dep.Version
		if dep.Replace != nil {
			// A local-path replacement has no version and fails below.
			v = dep.Replace.Version
		}
	}
	if !atLeast(v, 0, 31) {
		t.Fatalf("golang.org/x/crypto version %q is not v0.31.0 or later (CVE-2024-45337)", v)
	}
}

// atLeast reports whether a "vMAJOR.MINOR.PATCH" version is >= major.minor.
func atLeast(v string, major, minor int) bool {
	var ma, mi int
	rest := strings.TrimPrefix(v, "v")
	parts := strings.SplitN(rest, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, mi = atoi(parts[0]), atoi(parts[1])
	return ma > major || (ma == major && mi >= minor)
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}
