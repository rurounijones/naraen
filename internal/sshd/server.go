package sshd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/telemetry"
)

// Permission extension keys set by the key callback.
const (
	extIdentityID   = "identity-id"
	extIdentityKind = "identity-kind"
	extFingerprint  = "key-fingerprint"
)

const handshakeTimeout = 10 * time.Second

// Limits bound what any one client, authenticated or not, can hold open.
type Limits struct {
	// MaxConns caps concurrent connections in total.
	MaxConns int
	// MaxConnsPerSource caps concurrent connections from one source, so one
	// source cannot use up MaxConns. It bounds concurrency; ConnBurst and
	// ConnInterval bound rate.
	MaxConnsPerSource int
	// ConnBurst is how many connections one source may open at once before
	// ConnInterval applies. Connections over the rate are closed before the
	// handshake, so abandoned handshakes cannot keep the key exchange busy
	// (DHEat, CVE-2002-20001).
	ConnBurst int
	// ConnInterval is how often a source earns one more connection, up to
	// ConnBurst.
	ConnInterval time.Duration
	// MaxSessions caps session channels per connection.
	MaxSessions int
	// ConnLifetime is the most time a connection may stay open after the
	// handshake. git-lfs-authenticate is a single short exchange, and the
	// client simply reconnects for the next one.
	ConnLifetime time.Duration
	// AcceptBackoff is the first pause after a failed Accept, doubling up to
	// a second, so running out of file descriptors slows the listener down
	// instead of stopping it.
	AcceptBackoff time.Duration
}

// DefaultLimits are the limits the server runs with. Each git-lfs operation
// opens two connections (a git-lfs-transfer attempt, then
// git-lfs-authenticate), and the token it gets lasts 15 minutes, so a burst of
// 20 and 5 a second leave room for an office behind one NAT address while
// keeping one source to a few key exchanges a second.
var DefaultLimits = Limits{
	MaxConns:          256,
	MaxConnsPerSource: 8,
	ConnBurst:         20,
	ConnInterval:      200 * time.Millisecond,
	MaxSessions:       4,
	ConnLifetime:      time.Minute,
	AcceptBackoff:     initialAcceptBackoff,
}

const (
	initialAcceptBackoff = 5 * time.Millisecond
	maxAcceptBackoff     = time.Second
)

// NewServerConfig builds an SSH server config that allows public-key
// authentication only, with a modern-only algorithm set. Identity is taken
// solely from the Permissions returned by the callback for the authenticating
// key (CVE-2024-45337).
func NewServerConfig(hostKey ssh.Signer, a *authz.Authorizer) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: KeyCallback(a),
		ServerVersion:     "SSH-2.0-naraen",
	}
	cfg.KeyExchanges = []string{"mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org"}
	cfg.Ciphers = []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"}
	cfg.MACs = []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"}
	cfg.AddHostKey(hostKey)
	return cfg
}

// keyRefusedError records why the key callback refused a key, for the
// server's own audit record. x/crypto never sends callback errors to the
// client, which learns only that the key was not accepted.
type keyRefusedError struct {
	fingerprint string
	reason      authz.Reason
}

func (e *keyRefusedError) Error() string { return "unauthorized" }

// KeyCallback returns a PublicKeyCallback that accepts a key only if its
// fingerprint maps to an active identity. Failures reveal nothing.
func KeyCallback(a *authz.Authorizer) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		fp := ssh.FingerprintSHA256(key)
		id, err := a.IdentityForKey(fp)
		if err != nil {
			return nil, &keyRefusedError{fingerprint: fp, reason: authz.ReasonOf(err)}
		}
		return &ssh.Permissions{Extensions: map[string]string{
			extIdentityID:   id.ID,
			extIdentityKind: string(id.Kind),
			extFingerprint:  fp,
		}}, nil
	}
}

// refusedKey returns the last key refusal behind a failed handshake. A client
// offers its keys in turn, so the last one refused is the one it gave up on.
// It reports false for handshakes that failed for any other reason, such as a
// scanner disconnecting during key exchange.
func refusedKey(err error) (*keyRefusedError, bool) {
	var auth *ssh.ServerAuthError
	if !errors.As(err, &auth) {
		return nil, false
	}
	for i := len(auth.Errors) - 1; i >= 0; i-- {
		var refused *keyRefusedError
		if errors.As(auth.Errors[i], &refused) {
			return refused, true
		}
	}
	return nil, false
}

// Session describes the authenticated connection a command arrived on.
type Session struct {
	IdentityID   string
	IdentityKind string
	// Log carries the identity, its kind, the key fingerprint and the remote
	// address on every record, so each audit line stands alone.
	Log *slog.Logger
}

// Handler runs an authenticated, parsed command and returns what to print.
type Handler interface {
	Handle(ctx context.Context, s Session, cmd Command) (stdout []byte, err error)
}

// Serve accepts connections on ln until ctx is cancelled. It returns an error
// only if the listener is closed out from under it.
func Serve(ctx context.Context, ln net.Listener, cfg *ssh.ServerConfig, lim Limits, h Handler, rec *telemetry.Recorder, log *slog.Logger) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	rates := newRateLimiter(lim.ConnBurst, lim.ConnInterval, time.Now)
	conns := newConnLimiter(lim.MaxConns, lim.MaxConnsPerSource)
	backoff := lim.AcceptBackoff
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("sshd: accept: %w", err)
			}
			log.WarnContext(ctx, "ssh accept failed", "error", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = lim.AcceptBackoff
		src := sourceOf(conn.RemoteAddr())
		// Limit hits are logged at debug only: a flood would otherwise flood
		// the log too. The metric shows the volume and drives alerts.
		if !rates.allow(src) {
			log.DebugContext(ctx, "ssh connection rate limit reached", "remote", src)
			rec.ConnectionRejected(ctx, "rate")
			_ = conn.Close()
			continue
		}
		if !conns.acquire(src) {
			log.DebugContext(ctx, "ssh connection limit reached", "remote", src)
			rec.ConnectionRejected(ctx, "concurrency")
			_ = conn.Close()
			continue
		}
		go func() {
			defer conns.release(src)
			serveConn(ctx, conn, cfg, lim, h, rec, log)
		}()
	}
}

// nextBackoff doubles d, up to maxAcceptBackoff.
func nextBackoff(d time.Duration) time.Duration { return min(2*d, maxAcceptBackoff) }

// sourceOf returns the key that per-source limits count against: the address
// for IPv4, and the /64 prefix for IPv6, because a host is routinely given a
// whole /64 and could otherwise rotate addresses within it to escape every
// per-source limit. An address that is not an IP and port is used whole.
func sourceOf(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		return ip.String()
	}
	return netip.PrefixFrom(ip, 64).Masked().String()
}

// rateLimiter limits how often each source may connect, using the generic
// cell rate algorithm: a token bucket that keeps one time per source, the
// time at which that source's bucket would be full again. A source may connect
// while that time is at most (burst-1) intervals ahead of now, and each
// connection pushes it one interval further. Refused connections do not.
type rateLimiter struct {
	mu        sync.Mutex
	interval  time.Duration
	window    time.Duration
	now       func() time.Time
	fullAt    map[string]time.Time
	nextSweep time.Time
}

func newRateLimiter(burst int, interval time.Duration, now func() time.Time) *rateLimiter {
	return &rateLimiter{
		interval: interval,
		window:   time.Duration(burst-1) * interval,
		now:      now,
		fullAt:   make(map[string]time.Time),
	}
}

func (l *rateLimiter) allow(src string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)
	full := l.fullAt[src]
	if full.Before(now) {
		full = now
	}
	if full.Sub(now) > l.window {
		return false
	}
	l.fullAt[src] = full.Add(l.interval)
	return true
}

// sweep forgets sources whose bucket has refilled, since they are no
// different from sources never seen. It runs at most once per full refill
// period, so the map holds only sources that connected within about the last
// two refill periods, however many sources there are.
func (l *rateLimiter) sweep(now time.Time) {
	if now.Before(l.nextSweep) {
		return
	}
	for src, full := range l.fullAt {
		if !full.After(now) {
			delete(l.fullAt, src)
		}
	}
	l.nextSweep = now.Add(l.window + l.interval)
}

// connLimiter counts open connections in total and per source.
type connLimiter struct {
	mu       sync.Mutex
	maxTotal int
	perSrc   int
	total    int
	bySource map[string]int
}

func newConnLimiter(maxTotal, perSrc int) *connLimiter {
	return &connLimiter{maxTotal: maxTotal, perSrc: perSrc, bySource: make(map[string]int)}
}

func (l *connLimiter) acquire(src string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxTotal || l.bySource[src] >= l.perSrc {
		return false
	}
	l.total++
	l.bySource[src]++
	return true
}

func (l *connLimiter) release(src string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.bySource[src]--; l.bySource[src] == 0 {
		delete(l.bySource, src)
	}
}

func serveConn(ctx context.Context, nc net.Conn, cfg *ssh.ServerConfig, lim Limits, h Handler, rec *telemetry.Recorder, log *slog.Logger) {
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(handshakeTimeout))
	remote := nc.RemoteAddr().String()
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		if refused, ok := refusedKey(err); ok {
			log.InfoContext(ctx, "ssh authentication failed", "remote", remote,
				"fingerprint", refused.fingerprint, "reason", string(refused.reason))
			rec.AuthFailure(ctx, string(refused.reason), telemetry.IdentityTypeUnknown)
			return
		}
		log.DebugContext(ctx, "ssh handshake failed", "remote", remote)
		return
	}
	// The deadline bounds the whole connection, so an authenticated client
	// cannot hold it, or sessions waiting for a command, open indefinitely.
	deadline := time.Now().Add(lim.ConnLifetime)
	_ = nc.SetDeadline(deadline)
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	ext := conn.Permissions.Extensions
	s := Session{
		IdentityID:   ext[extIdentityID],
		IdentityKind: ext[extIdentityKind],
		Log: log.With("identity", ext[extIdentityID], "identity_type", ext[extIdentityKind],
			"fingerprint", ext[extFingerprint], "remote", remote),
	}
	s.Log.InfoContext(ctx, "ssh authenticated")

	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	serveChannels(ctx, chans, lim.MaxSessions, s, h, rec)
}

// serveChannels handles up to maxSessions session channels and rejects every
// other type.
func serveChannels(ctx context.Context, chans <-chan ssh.NewChannel, maxSessions int, s Session, h Handler, rec *telemetry.Recorder) {
	sessions := 0
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		if sessions >= maxSessions {
			_ = nch.Reject(ssh.ResourceShortage, "too many sessions")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		sessions++
		go serveSession(ctx, ch, creqs, s, h, rec)
	}
}

// reasonBadCommand labels exec payloads that do not parse. Path tricks such as
// ".." or encoded slashes land here, because the command parser normalizes
// the path, so the count is worth watching.
const reasonBadCommand = "bad_command"

// serveSession runs one exec request. Whatever goes wrong, the client hears
// only "request refused"; the reason goes to the log and the metrics.
func serveSession(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, s Session, h Handler, rec *telemetry.Recorder) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		raw, ok := parseExecPayload(req.Payload)
		cmd, err := ParseCommand(raw)
		if !ok || err != nil {
			// The raw command is client input of any size and content, so
			// it is not logged.
			s.Log.InfoContext(ctx, "command refused", "reason", reasonBadCommand)
			rec.AuthFailure(ctx, reasonBadCommand, s.IdentityKind)
			_ = req.Reply(false, nil)
			exit(ch, 1)
			return
		}
		_ = req.Reply(true, nil)
		out, err := h.Handle(ctx, s, cmd)
		if errors.Is(err, ErrUnsupported) {
			s.Log.InfoContext(ctx, "command unsupported", "command", cmd.Name, "repo", cmd.Repo, "operation", string(cmd.Op))
			_, _ = io.WriteString(ch.Stderr(), "error: "+ErrUnsupported.Error()+"\n")
			exit(ch, 1)
			return
		}
		if err != nil {
			if reason := authz.ReasonOf(err); reason != "" {
				s.Log.InfoContext(ctx, "command refused", "command", cmd.Name, "repo", cmd.Repo,
					"operation", string(cmd.Op), "reason", string(reason))
				rec.AuthFailure(ctx, string(reason), s.IdentityKind)
			} else {
				s.Log.ErrorContext(ctx, "command failed", "command", cmd.Name, "repo", cmd.Repo,
					"operation", string(cmd.Op), "error", err)
			}
			_, _ = io.WriteString(ch.Stderr(), "error: request refused\n")
			exit(ch, 1)
			return
		}
		_, _ = ch.Write(out)
		exit(ch, 0)
		return
	}
}

// parseExecPayload decodes the SSH "exec" request payload: a uint32 length
// followed by that many bytes, with nothing after.
func parseExecPayload(p []byte) (string, bool) {
	if len(p) < 4 {
		return "", false
	}
	n := binary.BigEndian.Uint32(p)
	if int64(n) != int64(len(p)-4) {
		return "", false
	}
	return string(p[4:]), true
}

func exit(ch ssh.Channel, code uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], code)
	_, _ = ch.SendRequest("exit-status", false, b[:])
}
