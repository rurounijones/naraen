package sshd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/telemetry"
)

type recordingHandler struct {
	got    Session
	gotCmd Command
	out    []byte
	err    error
}

func (h *recordingHandler) Handle(_ context.Context, s Session, c Command) ([]byte, error) {
	h.got, h.gotCmd = s, c
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

func startWith(t *testing.T, known ssh.Signer, h Handler, lim Limits) (addr string, hostPub ssh.PublicKey) {
	t.Helper()
	o := startObserved(t, known, h, lim)
	return o.addr, o.hostPub
}

// observed is a running server whose log records, metrics and spans a test
// can read.
type observed struct {
	addr    string
	hostPub ssh.PublicKey
	logs    *syncBuffer
	metrics *sdkmetric.ManualReader
	spans   *tracetest.SpanRecorder
	traces  *sdktrace.TracerProvider
}

func startObserved(t *testing.T, known ssh.Signer, h Handler, lim Limits) *observed {
	t.Helper()
	host := newSigner(t)
	cfg := NewServerConfig(host, authz.New(storeKnowing(t, known)))
	o := &observed{hostPub: host.PublicKey(), logs: &syncBuffer{}, metrics: sdkmetric.NewManualReader(), spans: tracetest.NewSpanRecorder()}
	o.traces = sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(o.spans))
	log := slog.New(slog.NewJSONHandler(o.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rec := telemetry.NewRecorder(sdkmetric.NewMeterProvider(sdkmetric.WithReader(o.metrics)))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, cfg, lim, h, o.traces, rec, log) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	o.addr = ln.Addr().String()
	return o
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
	o := startObserved(t, alice, h, DefaultLimits)

	c, err := dial(o.addr, o.hostPub, alice)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	out, err := run(c, "git-lfs-authenticate Acme/Assets.git download")
	if err != nil || out != `{"href":"x"}` {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	if h.got.IdentityID != "alice" || h.got.IdentityKind != "person" || h.gotCmd.Repo != "acme/assets" || h.gotCmd.Name != CmdAuthenticate {
		t.Errorf("handler saw %+v %+v", h.got, h.gotCmd)
	}
	// The session's logger puts the connection on every record.
	r := o.logs.record(t, "ssh authenticated")
	checkFields(t, r, map[string]string{
		"identity":      "alice",
		"identity_type": "person",
		"fingerprint":   ssh.FingerprintSHA256(alice.PublicKey()),
	})
	if remote, _ := r["remote"].(string); !strings.HasPrefix(remote, "127.0.0.1:") {
		t.Errorf("remote = %v", r["remote"])
	}

	// The connection is a trace of its own, holding the command's span, and
	// the records logged in it carry its IDs.
	exec := o.span(t, "ssh exec", map[string]string{
		telemetry.AttrCommand: CmdAuthenticate, telemetry.AttrRepo: "acme/assets", telemetry.AttrOperation: "download",
	})
	c.Close()
	conn := o.span(t, "ssh connection", map[string]string{
		telemetry.AttrIdentity: "alice", telemetry.AttrIdentityType: "person",
		telemetry.AttrFingerprint: ssh.FingerprintSHA256(alice.PublicKey()), "network.peer.address": "127.0.0.1",
	})
	if conn.Parent().IsValid() || conn.SpanKind() != trace.SpanKindServer || exec.Parent().SpanID() != conn.SpanContext().SpanID() {
		t.Errorf("connection %v (kind %v) does not hold exec %v", conn.SpanContext(), conn.SpanKind(), exec.Parent())
	}
	if exec.Status().Code != codes.Unset {
		t.Errorf("exec status = %v", exec.Status())
	}
}

func TestServeRefusals(t *testing.T) {
	alice := newSigner(t)
	h := &recordingHandler{err: errors.New("nope")}
	o := startObserved(t, alice, h, DefaultLimits)
	c, err := dial(o.addr, o.hostPub, alice)
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
	// A command that does not parse, such as a path trick, is counted and
	// logged without echoing the client's input.
	r := o.logs.record(t, "command refused")
	checkFields(t, r, map[string]string{"reason": "bad_command", "identity": "alice"})
	if strings.Contains(o.logs.String(), "ls -la") {
		t.Error("raw command logged")
	}
	waitCount(t, o.metrics, telemetry.MetricAuthFailures, "identity_type=person,reason=bad_command", 1)
	if s := o.span(t, "ssh exec", map[string]string{telemetry.AttrReason: "bad_command"}); len(s.Attributes()) != 1 {
		t.Errorf("unparseable command's span holds %v", s.Attributes())
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

// stderrOf runs cmd and returns what it wrote to stderr and its error.
func stderrOf(t *testing.T, c *ssh.Client, cmd string) (string, error) {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	var stderr strings.Builder
	sess.Stderr = &stderr
	err = sess.Run(cmd)
	return stderr.String(), err
}

// A refusal names no reason, but git-lfs-transfer being unsupported is not a
// refusal of access and is said plainly, so git-lfs falls back at once. The
// server's own record says what happened in each case.
func TestServeReportsUnsupportedAndRefusedDifferently(t *testing.T) {
	alice := newSigner(t)
	// A real denial, carrying the reason only the server sees.
	_, denied := authz.New(datastore.NewStore(time.Hour, datastore.DefaultLimits)).Authorize("alice", "acme/assets", lfs.Upload)
	for _, tt := range []struct {
		err    error
		stderr string
		record string
		fields map[string]string
		metric string // auth.failures point that must reach 1, "" for none
		reason string // the exec span's reason, "" for none
	}{
		{
			ErrUnsupported, "error: git-lfs-transfer is not supported\n", "command unsupported",
			map[string]string{"command": CmdTransfer, "repo": "acme/assets", "operation": "upload"},
			"", "unsupported",
		},
		{
			denied, "error: request refused\n", "command refused",
			map[string]string{"command": CmdTransfer, "repo": "acme/assets", "operation": "upload", "reason": "not_ready"},
			"identity_type=person,reason=not_ready", "not_ready",
		},
		{
			errors.New("secret"), "error: request refused\n", "command failed",
			map[string]string{"command": CmdTransfer, "error": "secret", "level": "ERROR"},
			"", "",
		},
	} {
		o := startObserved(t, alice, &recordingHandler{err: tt.err}, DefaultLimits)
		c, err := dial(o.addr, o.hostPub, alice)
		if err != nil {
			t.Fatal(err)
		}
		stderr, err := stderrOf(t, c, "git-lfs-transfer acme/assets upload")
		c.Close()
		var exitErr *ssh.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 1 || stderr != tt.stderr {
			t.Errorf("%v: stderr = %q, err = %v", tt.err, stderr, err)
		}
		r := o.logs.record(t, tt.record)
		checkFields(t, r, tt.fields)
		checkFields(t, r, map[string]string{"identity": "alice"})
		// Only an internal failure is an error on the span; a refusal is the
		// server working.
		s := o.span(t, "ssh exec", map[string]string{telemetry.AttrCommand: CmdTransfer, telemetry.AttrReason: tt.reason})
		if failed := tt.reason == ""; (s.Status().Code == codes.Error) != failed || (len(s.Events()) == 1) != failed {
			t.Errorf("%v: span status %v, events %v", tt.err, s.Status(), s.Events())
		}
		if tt.metric == "" {
			if got := counts(t, o.metrics, telemetry.MetricAuthFailures); len(got) != 0 {
				t.Errorf("%v: counted as an auth failure: %v", tt.err, got)
			}
			continue
		}
		waitCount(t, o.metrics, telemetry.MetricAuthFailures, tt.metric, 1)
	}
}

// An unknown key is refused without telling the client why, and the server
// records which key was offered from where.
func TestServeRejectsUnknownKey(t *testing.T) {
	alice, mallory := newSigner(t), newSigner(t)
	o := startObserved(t, alice, &recordingHandler{}, DefaultLimits)
	if c, err := dial(o.addr, o.hostPub, mallory); err == nil {
		c.Close()
		t.Fatal("unknown key authenticated")
	}
	r := o.logs.record(t, "ssh authentication failed")
	checkFields(t, r, map[string]string{"reason": "unknown_key", "fingerprint": ssh.FingerprintSHA256(mallory.PublicKey())})
	if remote, _ := r["remote"].(string); !strings.HasPrefix(remote, "127.0.0.1:") {
		t.Errorf("remote = %v", r["remote"])
	}
	waitCount(t, o.metrics, telemetry.MetricAuthFailures, "identity_type=unknown,reason=unknown_key", 1)
	o.span(t, "ssh connection", map[string]string{
		telemetry.AttrReason: "unknown_key", telemetry.AttrFingerprint: ssh.FingerprintSHA256(mallory.PublicKey()),
	})
}

// A handshake that fails without any key being refused, here a password
// attempt, is not an authentication failure: scanners do this all day.
func TestServeRejectsPasswordAuth(t *testing.T) {
	alice := newSigner(t)
	o := startObserved(t, alice, &recordingHandler{}, DefaultLimits)
	_, err := ssh.Dial("tcp", o.addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.Password("hunter2")},
		HostKeyCallback: ssh.FixedHostKey(o.hostPub),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("password auth succeeded")
	}
	checkFields(t, o.logs.record(t, "ssh handshake failed"), map[string]string{"level": "DEBUG"})
	if got := counts(t, o.metrics, telemetry.MetricAuthFailures); len(got) != 0 {
		t.Errorf("counted as an auth failure: %v", got)
	}
	if strings.Contains(o.logs.String(), "hunter2") {
		t.Error("password logged")
	}
	o.span(t, "ssh connection", map[string]string{telemetry.AttrReason: "handshake_failed"})
}

// Only a TCP address is split into address and port.
func TestPeerAttrs(t *testing.T) {
	got := attribute.NewSet(peerAttrs(&net.TCPAddr{IP: net.IPv6loopback, Port: 22})...)
	addr, _ := got.Value("network.peer.address")
	port, _ := got.Value("network.peer.port")
	if addr.AsString() != "::1" || port.AsInt64() != 22 || got.Len() != 2 {
		t.Errorf("tcp: %v", got.ToSlice())
	}
	unix := attribute.NewSet(peerAttrs(&net.UnixAddr{Name: "/run/naraen.sock", Net: "unix"})...)
	if addr, _ := unix.Value("network.peer.address"); addr.AsString() != "/run/naraen.sock" || unix.Len() != 1 {
		t.Errorf("unix: %v", unix.ToSlice())
	}
}

func TestRefusedKey(t *testing.T) {
	first := &keyRefusedError{fingerprint: "SHA256:first", reason: authz.ReasonUnknownKey}
	last := &keyRefusedError{fingerprint: "SHA256:last", reason: authz.ReasonInactiveIdentity}
	got, ok := refusedKey(&ssh.ServerAuthError{Errors: []error{ssh.ErrNoAuth, first, last, errors.New("later failure")}})
	if !ok || got != last {
		t.Errorf("refusedKey = %+v, %v; want the last refusal", got, ok)
	}
	// The search reaches the first entry too.
	if got, ok := refusedKey(&ssh.ServerAuthError{Errors: []error{first, ssh.ErrNoAuth}}); !ok || got != first {
		t.Errorf("refusedKey = %+v, %v; want the only refusal", got, ok)
	}
	for name, err := range map[string]error{
		"no key offered": &ssh.ServerAuthError{Errors: []error{ssh.ErrNoAuth}},
		"not auth":       errors.New("connection reset"),
		"nil":            nil,
	} {
		if got, ok := refusedKey(err); ok || got != nil {
			t.Errorf("%s: refusedKey = %+v, %v", name, got, ok)
		}
	}
	if first.Error() != "unauthorized" {
		t.Errorf("Error() = %q", first.Error())
	}
}

func TestServeLimitsConnectionsPerSource(t *testing.T) {
	alice := newSigner(t)
	lim := DefaultLimits
	lim.MaxConnsPerSource = 1
	o := startObserved(t, alice, &recordingHandler{}, lim)
	addr, hostPub := o.addr, o.hostPub
	first, err := dial(addr, hostPub, alice)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := dial(addr, hostPub, alice); err == nil {
		c.Close()
		t.Fatal("second connection from the same source accepted")
	}
	waitCount(t, o.metrics, telemetry.MetricSSHConnsRejected, "reason=concurrency", 1)
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
	if perms.Extensions[extIdentityID] != "alice" || perms.Extensions[extIdentityKind] != "person" ||
		perms.Extensions[extFingerprint] != ssh.FingerprintSHA256(alice.PublicKey()) {
		t.Errorf("extensions = %v", perms.Extensions)
	}
	stranger := newSigner(t).PublicKey()
	_, err = cb(nil, stranger)
	var refused *keyRefusedError
	if !errors.As(err, &refused) || refused.reason != authz.ReasonUnknownKey || refused.fingerprint != ssh.FingerprintSHA256(stranger) {
		t.Errorf("unknown key: %v (%+v)", err, refused)
	}
	// The reason comes from authz, so a store that is not ready says so.
	_, err = KeyCallback(authz.New(datastore.NewStore(time.Hour, datastore.DefaultLimits)))(nil, alice.PublicKey())
	if !errors.As(err, &refused) || refused.reason != authz.ReasonNotReady {
		t.Errorf("not ready: %v (%+v)", err, refused)
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
	serveChannels(context.Background(), chans, 1, Session{Log: quiet()}, &recordingHandler{}, noRec())
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
	serveChannels(context.Background(), chans, 1, Session{Log: quiet()}, &recordingHandler{}, noRec())
	if later.rejected {
		t.Fatal("channels after an accept error must not be processed")
	}
}

func TestServeChannelsRejectsSessionsOverLimit(t *testing.T) {
	chans := make(chan ssh.NewChannel, 1)
	over := &fakeChannel{typ: "session", acceptEr: errors.New("must not be accepted")}
	chans <- over
	close(chans)
	serveChannels(context.Background(), chans, 0, Session{Log: quiet()}, &recordingHandler{}, noRec())
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
	err := Serve(context.Background(), ln, &ssh.ServerConfig{}, lim, &recordingHandler{}, tracenoop.NewTracerProvider(), noRec(), quiet())
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
	go func() {
		done <- Serve(ctx, ln, &ssh.ServerConfig{}, lim, &recordingHandler{}, tracenoop.NewTracerProvider(), noRec(), quiet())
	}()
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
	o := startObserved(t, alice, &recordingHandler{}, lim)
	c, err := dial(o.addr, o.hostPub, alice)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// The first connection has ended, so only the rate can refuse this one.
	if c, err := dial(o.addr, o.hostPub, alice); err == nil {
		c.Close()
		t.Fatal("connection over the rate accepted")
	}
	waitCount(t, o.metrics, telemetry.MetricSSHConnsRejected, "reason=rate", 1)
	if got := counts(t, o.metrics, telemetry.MetricSSHConnsRejected); len(got) != 1 {
		t.Errorf("rejections = %v, want only the rate", got)
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
