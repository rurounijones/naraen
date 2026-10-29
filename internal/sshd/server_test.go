package sshd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/datastore"
)

type recordingHandler struct {
	gotID  string
	gotCmd Command
	out    []byte
	err    error
}

func (h *recordingHandler) Handle(_ context.Context, id string, c Command) ([]byte, error) {
	h.gotID, h.gotCmd = id, c
	return h.out, h.err
}

func newSigner(t *testing.T) ssh.Signer {
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

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// storeKnowing returns a ready store whose only identity, alice, owns known.
func storeKnowing(t *testing.T, known ssh.Signer) *datastore.Store {
	t.Helper()
	snap, err := datastore.NewSnapshot(datastore.Data{
		Identities: []datastore.Identity{{ID: "alice", Kind: datastore.KindPerson, Active: true}},
		Keys:       []datastore.Key{{Fingerprint: ssh.FingerprintSHA256(known.PublicKey()), IdentityID: "alice"}},
		Repos:      []datastore.Repo{{ID: "r1", Path: "acme/assets"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	st := datastore.NewStore(time.Hour, datastore.DefaultLimits)
	if err := st.Swap(st.StartSync(), snap); err != nil {
		t.Fatal(err)
	}
	return st
}

// start runs a server with DefaultLimits whose datastore knows only the given
// client signer.
func start(t *testing.T, known ssh.Signer, h Handler) (addr string, hostPub ssh.PublicKey) {
	t.Helper()
	return startWith(t, known, h, DefaultLimits)
}

func startWith(t *testing.T, known ssh.Signer, h Handler, lim Limits) (addr string, hostPub ssh.PublicKey) {
	t.Helper()
	host := newSigner(t)
	cfg := NewServerConfig(host, authz.New(storeKnowing(t, known)))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, cfg, lim, h, quiet()) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String(), host.PublicKey()
}

// dial bounds the whole handshake, not just the TCP connect, so a server that
// accepts but never answers fails the test instead of hanging it.
func dial(addr string, hostPub ssh.PublicKey, signers ...ssh.Signer) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
	}
	nc, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return nil, err
	}
	_ = nc.SetDeadline(time.Now().Add(time.Second))
	c, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

func run(c *ssh.Client, cmd string) (string, error) {
	sess, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output(cmd)
	return string(out), err
}

func TestServeKnownKeyRunsCommand(t *testing.T) {
	alice := newSigner(t)
	h := &recordingHandler{out: []byte(`{"href":"x"}`)}
	addr, hostPub := start(t, alice, h)

	c, err := dial(addr, hostPub, alice)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	out, err := run(c, "git-lfs-authenticate Acme/Assets.git download")
	if err != nil || out != `{"href":"x"}` {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	if h.gotID != "alice" || h.gotCmd.Repo != "acme/assets" || h.gotCmd.Name != CmdAuthenticate {
		t.Errorf("handler saw %q %+v", h.gotID, h.gotCmd)
	}
}

func TestServeRefusals(t *testing.T) {
	alice := newSigner(t)
	h := &recordingHandler{err: errors.New("nope")}
	addr, hostPub := start(t, alice, h)
	c, err := dial(addr, hostPub, alice)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := run(c, "git-lfs-transfer acme/assets download"); err == nil {
		t.Error("handler error must give a non-zero exit")
	}
	if _, err := run(c, "ls -la"); err == nil {
		t.Error("unparseable command must be refused")
	}
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Shell(); err == nil {
		t.Error("interactive shell must be refused")
	}
}

func TestServeRejectsUnknownKey(t *testing.T) {
	alice, mallory := newSigner(t), newSigner(t)
	addr, hostPub := start(t, alice, &recordingHandler{})
	if c, err := dial(addr, hostPub, mallory); err == nil {
		c.Close()
		t.Fatal("unknown key authenticated")
	}
}

func TestServeRejectsPasswordAuth(t *testing.T) {
	alice := newSigner(t)
	addr, hostPub := start(t, alice, &recordingHandler{})
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.Password("hunter2")},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("password auth succeeded")
	}
}

func TestServeLimitsConnectionsPerSource(t *testing.T) {
	alice := newSigner(t)
	lim := DefaultLimits
	lim.MaxConnsPerSource = 1
	addr, hostPub := startWith(t, alice, &recordingHandler{}, lim)
	first, err := dial(addr, hostPub, alice)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := dial(addr, hostPub, alice); err == nil {
		c.Close()
		t.Fatal("second connection from the same source accepted")
	}
	first.Close()
	// The slot is released once the first connection ends.
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := dial(addr, hostPub, alice)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot never released: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeLimitsSessions(t *testing.T) {
	alice := newSigner(t)
	lim := DefaultLimits
	lim.MaxSessions = 1
	addr, hostPub := startWith(t, alice, &recordingHandler{}, lim)
	c, err := dial(addr, hostPub, alice)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s1, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	if s2, err := c.NewSession(); err == nil {
		s2.Close()
		t.Fatal("second session accepted over MaxSessions")
	}
}

func TestServeClosesConnectionAfterLifetime(t *testing.T) {
	alice := newSigner(t)
	lim := DefaultLimits
	lim.ConnLifetime = 200 * time.Millisecond
	addr, hostPub := startWith(t, alice, &recordingHandler{}, lim)
	c, err := dial(addr, hostPub, alice)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan struct{})
	go func() {
		_ = c.Wait() // the server closing the connection is the expected outcome
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle authenticated connection outlived ConnLifetime")
	}
}

func TestServerConfigAlgorithms(t *testing.T) {
	cfg := NewServerConfig(newSigner(t), authz.New(datastore.NewStore(time.Hour, datastore.DefaultLimits)))
	banned := []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "aes128-cbc", "3des-cbc", "arcfour", "hmac-sha1", "hmac-md5"}
	all := append(append(append([]string{}, cfg.KeyExchanges...), cfg.Ciphers...), cfg.MACs...)
	for _, a := range all {
		for _, b := range banned {
			if a == b {
				t.Errorf("weak algorithm %q configured", a)
			}
		}
	}
	if cfg.NoClientAuth || cfg.PasswordCallback != nil || cfg.KeyboardInteractiveCallback != nil {
		t.Error("only public-key auth may be enabled")
	}
	if cfg.PublicKeyCallback == nil {
		t.Error("public key callback missing")
	}
}

func TestKeyCallbackCarriesIdentityOfAuthenticatingKey(t *testing.T) {
	alice := newSigner(t)
	cb := KeyCallback(authz.New(storeKnowing(t, alice)))

	perms, err := cb(nil, alice.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if perms.Extensions[extIdentityID] != "alice" || perms.Extensions[extFingerprint] != ssh.FingerprintSHA256(alice.PublicKey()) {
		t.Errorf("extensions = %v", perms.Extensions)
	}
	if _, err := cb(nil, newSigner(t).PublicKey()); err == nil {
		t.Error("unknown key accepted")
	}
}

func TestParseExecPayload(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
		ok   bool
	}{
		{"valid", []byte{0, 0, 0, 2, 'h', 'i'}, "hi", true},
		{"empty command", []byte{0, 0, 0, 0}, "", true},
		{"too short", []byte{0, 0, 1}, "", false},
		{"length exceeds data", []byte{0, 0, 0, 5, 'h', 'i'}, "", false},
		{"trailing data", []byte{0, 0, 0, 1, 'h', 'i'}, "", false},
		{"huge length", []byte{0xff, 0xff, 0xff, 0xff, 'h'}, "", false},
		{"nil", nil, "", false},
	}
	for _, tt := range tests {
		got, ok := parseExecPayload(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("%s: got %q, %v", tt.name, got, ok)
		}
	}
}

type fakeChannel struct {
	typ      string
	acceptEr error
	rejected bool
	reason   ssh.RejectionReason
}

func (f *fakeChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, f.acceptEr
}

func (f *fakeChannel) Reject(r ssh.RejectionReason, _ string) error {
	f.rejected, f.reason = true, r
	return nil
}
func (f *fakeChannel) ChannelType() string { return f.typ }
func (f *fakeChannel) ExtraData() []byte   { return nil }

func TestServeChannelsRejectsNonSession(t *testing.T) {
	chans := make(chan ssh.NewChannel, 1)
	other := &fakeChannel{typ: "direct-tcpip"}
	chans <- other
	close(chans)
	serveChannels(context.Background(), chans, 1, "id", &recordingHandler{}, quiet())
	if !other.rejected || other.reason != ssh.UnknownChannelType {
		t.Fatal("non-session channel was not rejected")
	}
}

func TestServeChannelsStopsOnAcceptError(t *testing.T) {
	chans := make(chan ssh.NewChannel, 2)
	bad := &fakeChannel{typ: "session", acceptEr: errors.New("boom")}
	later := &fakeChannel{typ: "x"}
	chans <- bad
	chans <- later
	close(chans)
	serveChannels(context.Background(), chans, 1, "id", &recordingHandler{}, quiet())
	if later.rejected {
		t.Fatal("channels after an accept error must not be processed")
	}
}

func TestServeChannelsRejectsSessionsOverLimit(t *testing.T) {
	chans := make(chan ssh.NewChannel, 1)
	over := &fakeChannel{typ: "session", acceptEr: errors.New("must not be accepted")}
	chans <- over
	close(chans)
	serveChannels(context.Background(), chans, 0, "id", &recordingHandler{}, quiet())
	if !over.rejected || over.reason != ssh.ResourceShortage {
		t.Fatal("session over the limit was not rejected")
	}
}

// flakyListener fails Accept with a transient error a number of times, then
// reports that it is closed.
type flakyListener struct {
	net.Listener
	failures int
	calls    chan struct{}
}

func (f *flakyListener) Accept() (net.Conn, error) {
	f.calls <- struct{}{}
	if f.failures > 0 {
		f.failures--
		return nil, errors.New("too many open files")
	}
	return nil, net.ErrClosed
}
func (*flakyListener) Close() error { return nil }

func TestServeRetriesTransientAcceptErrors(t *testing.T) {
	ln := &flakyListener{failures: 3, calls: make(chan struct{}, 10)}
	lim := DefaultLimits
	lim.AcceptBackoff = time.Millisecond
	err := Serve(context.Background(), ln, &ssh.ServerConfig{}, lim, &recordingHandler{}, quiet())
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("err = %v, want net.ErrClosed", err)
	}
	if n := len(ln.calls); n != 4 {
		t.Fatalf("Accept called %d times, want 4", n)
	}
}

func TestServeStopsDuringBackoff(t *testing.T) {
	ln := &flakyListener{failures: 1, calls: make(chan struct{}, 10)}
	lim := DefaultLimits
	lim.AcceptBackoff = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, &ssh.ServerConfig{}, lim, &recordingHandler{}, quiet()) }()
	<-ln.calls
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop while backing off")
	}
}

func TestNextBackoff(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		5 * time.Millisecond:   10 * time.Millisecond,
		400 * time.Millisecond: 800 * time.Millisecond,
		800 * time.Millisecond: time.Second,
		time.Second:            time.Second,
	} {
		if got := nextBackoff(in); got != want {
			t.Errorf("nextBackoff(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestConnLimiter(t *testing.T) {
	l := newConnLimiter(3, 2)
	for i := range 2 {
		if !l.acquire("a") {
			t.Fatalf("connection %d from a refused", i+1)
		}
	}
	if l.acquire("a") {
		t.Fatal("third from a accepted over the per-source cap")
	}
	if !l.acquire("b") {
		t.Fatal("b refused below the total cap")
	}
	if l.acquire("c") {
		t.Fatal("accepted over the total cap")
	}
	l.release("a")
	if !l.acquire("c") {
		t.Fatal("release did not free a total slot")
	}
	l.release("b")
	if _, ok := l.bySource["b"]; ok {
		t.Fatal("source with no connections kept in the map")
	}
	if l.bySource["a"] != 1 || l.total != 2 {
		t.Fatalf("counts after releases: a=%d total=%d", l.bySource["a"], l.total)
	}
}

type fakeAddr string

func (fakeAddr) Network() string  { return "test" }
func (a fakeAddr) String() string { return string(a) }

// fakeClock is a settable time source for the rate limiter.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestRateLimiter(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := newRateLimiter(3, time.Second, clock.now)
	for i := range 3 {
		if !l.allow("a") {
			t.Fatalf("connection %d of the burst refused", i+1)
		}
	}
	if l.allow("a") {
		t.Fatal("connection over the burst accepted")
	}
	if !l.allow("b") {
		t.Fatal("another source refused because of a")
	}
	// Refused attempts do not push the refill back.
	l.allow("a")
	clock.advance(time.Second - time.Nanosecond)
	if l.allow("a") {
		t.Fatal("accepted before an interval had passed")
	}
	clock.advance(time.Nanosecond)
	if !l.allow("a") {
		t.Fatal("refused after one interval")
	}
	if l.allow("a") {
		t.Fatal("one interval earned more than one connection")
	}
	// A bucket refills to the burst and no further.
	clock.advance(time.Hour)
	for i := range 3 {
		if !l.allow("a") {
			t.Fatalf("connection %d after refilling refused", i+1)
		}
	}
	if l.allow("a") {
		t.Fatal("a long idle period earned more than the burst")
	}
}

func TestRateLimiterSweepsRefilledSources(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := newRateLimiter(2, time.Second, clock.now)
	l.allow("a")
	l.allow("a")
	l.allow("b")
	// The first call swept an empty map; the next sweep is due one refill
	// period (two intervals) later.
	clock.advance(2*time.Second - time.Nanosecond)
	l.allow("c")
	if len(l.fullAt) != 3 {
		t.Fatalf("swept early: %v", l.fullAt)
	}
	clock.advance(time.Nanosecond)
	l.allow("c")
	// b refilled after one interval and a exactly now; c is still draining.
	if _, ok := l.fullAt["a"]; ok {
		t.Fatal("source refilled at the sweep time was kept")
	}
	if _, ok := l.fullAt["b"]; ok {
		t.Fatal("refilled source was kept")
	}
	if _, ok := l.fullAt["c"]; !ok {
		t.Fatal("source still refilling was forgotten")
	}
}

func TestServeLimitsConnectionRate(t *testing.T) {
	alice := newSigner(t)
	lim := DefaultLimits
	lim.ConnBurst = 1
	lim.ConnInterval = time.Hour
	addr, hostPub := startWith(t, alice, &recordingHandler{}, lim)
	c, err := dial(addr, hostPub, alice)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// The first connection has ended, so only the rate can refuse this one.
	if c, err := dial(addr, hostPub, alice); err == nil {
		c.Close()
		t.Fatal("connection over the rate accepted")
	}
}

func TestSourceOf(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1:2222":            "192.0.2.1",
		"[::ffff:192.0.2.1]:22":     "192.0.2.1",
		"[2001:db8::1]:22":          "2001:db8::/64",
		"[2001:db8::ffff:1:2:3]:22": "2001:db8::/64",
		"[fe80::1%eth0]:22":         "fe80::/64",
		"example.com:22":            "example.com",
		"@unix-socket":              "@unix-socket",
	} {
		if got := sourceOf(fakeAddr(in)); got != want {
			t.Errorf("sourceOf(%q) = %q, want %q", in, got, want)
		}
	}
}
