package github

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rurounijones/naraen/internal/provider"
	"github.com/rurounijones/naraen/internal/telemetry"
)

const (
	// maxPages bounds one listing, so a broken or hostile Link header cannot
	// keep a sync paging forever. At 100 items a page that is 100,000 items.
	maxPages = 1000
	// appJWTLifetime is the App JWT's lifetime; GitHub allows at most ten
	// minutes.
	appJWTLifetime = 9 * time.Minute
	// tokenRefresh renews an installation token this long before it
	// expires, so a token never lapses in the middle of a sync.
	tokenRefresh = 5 * time.Minute
	// maxRateLimitWait is the longest a request waits out GitHub's rate
	// limit. A longer pause fails the sync instead: a snapshot's age counts
	// from when its sync began, so one that waited longer would be published
	// already old, and the next scheduled sync is as good a retry.
	maxRateLimitWait = 5 * time.Minute
	// maxRateLimitRetries bounds the retries of a request GitHub keeps
	// refusing for its rate limit.
	maxRateLimitRetries = 3
)

// ParseAppKey reads a GitHub App private key, which GitHub issues as a PKCS #1
// PEM block; PKCS #8 is accepted too.
func ParseAppKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("github: app key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("github: app key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github: app key is not RSA")
	}
	return rk, nil
}

// AppAuth mints and caches installation access tokens for a GitHub App. The
// App's private key is its only credential; installation tokens last an hour
// and are scoped to the App's permissions on one installation.
type AppAuth struct {
	BaseURL        string
	AppID          string
	InstallationID string
	Key            *rsa.PrivateKey
	HTTP           *http.Client
	// Now is replaceable in tests.
	Now func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Token returns a valid installation token, minting a new one when the cached
// one is near expiry.
func (a *AppAuth) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.Now()
	// Before the first token, expires is zero, so this is false.
	if now.Add(tokenRefresh).Before(a.expires) {
		return a.token, nil
	}
	jwt, err := a.appJWT(now)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.BaseURL+"/app/installations/"+url.PathEscape(a.InstallationID)+"/access_tokens", nil)
	if err != nil {
		return "", fmt.Errorf("github: token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: installation token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("github: installation token: status %d", resp.StatusCode)
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPage)).Decode(&out); err != nil || len(out.Token) == 0 {
		return "", errors.New("github: installation token: malformed response")
	}
	a.token, a.expires = out.Token, out.ExpiresAt
	return a.token, nil
}

// appJWT signs the short-lived RS256 JWT that authenticates the App itself.
// iat is backdated a minute to absorb clock skew, as GitHub recommends.
func (a *AppAuth) appJWT(now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(appJWTLifetime).Unix(), "iss": a.AppID,
	})
	input := header + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(nil, a.Key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("github: sign app jwt: %w", err)
	}
	return input + "." + enc.EncodeToString(sig), nil
}

// Client reads the GitHub REST API as an App installation.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	Token   func(context.Context) (string, error)
	// Now and Sleep are replaceable in tests; main sets time.Now and Sleep.
	Now   func() time.Time
	Sleep func(context.Context, time.Duration) error
	// Log and Rec report each rate-limit refusal and the time requests were
	// held back for it, so a sync slowed by a wait is visible while it waits.
	Log *slog.Logger
	Rec *telemetry.Recorder

	mu sync.Mutex
	// resume is when GitHub's rate limit allows requests again. No request
	// is sent before then, from this sync or a later one.
	resume time.Time
}

// Sleep waits for d, or until ctx is done.
func Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-t.C:
		return nil
	}
}

// rateLimited is a request GitHub refused for its rate limit.
type rateLimited struct {
	path string
	wait time.Duration
}

func (e *rateLimited) Error() string {
	return fmt.Sprintf("github: %s: rate limited, retry after %s", e.path, e.wait)
}

func (e *rateLimited) Unwrap() error { return provider.ErrRateLimited }

// response is one page as GitHub answered it.
type response struct {
	body       []byte
	link, etag string
	// notModified reports a 304 to a request that sent an ETag.
	notModified bool
}

// get reads u. With etag set it asks for the page only if it has changed
// since, and a 304 comes back as notModified.
//
// A request refused for the rate limit is retried after the wait GitHub asks
// for, at most maxRateLimitRetries times, and the wait holds back every
// other request too: GitHub warns that an integration which keeps sending
// requests while limited may be banned.
func (c *Client) get(ctx context.Context, u, etag string) (response, error) {
	for attempt := 0; ; attempt++ {
		if err := c.awaitResume(ctx); err != nil {
			return response{}, err
		}
		resp, err := c.do(ctx, u, etag, attempt)
		var limited *rateLimited
		if !errors.As(err, &limited) {
			return resp, err
		}
		resume := c.pause(ctx, limited.wait)
		c.Log.WarnContext(ctx, "github rate limit: holding requests back",
			"path", limited.path, "wait", limited.wait, "resume", resume, "attempt", attempt+1)
		if attempt == maxRateLimitRetries {
			return response{}, err
		}
	}
}

// awaitResume waits until the rate limit allows requests again, or fails at
// once if that is more than maxRateLimitWait away. It checks again after
// waiting, since another request may have extended the pause meanwhile.
func (c *Client) awaitResume(ctx context.Context) error {
	for {
		c.mu.Lock()
		resume := c.resume
		c.mu.Unlock()
		d := resume.Sub(c.Now())
		if d <= 0 {
			return nil
		}
		if d > maxRateLimitWait {
			return fmt.Errorf("github: %w until %s", provider.ErrRateLimited, resume.UTC().Format(time.RFC3339))
		}
		if err := c.Sleep(ctx, d); err != nil {
			return fmt.Errorf("github: waiting out the rate limit: %w", err)
		}
	}
}

// pause holds every request back for d, or for longer if already paused
// longer, and returns when requests may resume. Only the time by which it
// extends the hold is counted, so requests refused together are not counted
// once each.
func (c *Client) pause(ctx context.Context, d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.Now()
	if until := now.Add(d); until.After(c.resume) {
		c.Rec.RateLimitWait(ctx, until.Sub(later(now, c.resume)))
		c.resume = until
	}
	return c.resume
}

// later returns the later of a and b.
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// limitWait reports whether GitHub refused resp for its rate limit, and how
// long to wait before retrying, in the order GitHub documents: the seconds
// in Retry-After; else, with no requests remaining, until the reset time;
// else a minute, doubling with each retry. A 429 is always a rate limit, but
// a 403 only when its headers or message say so; otherwise it is a missing
// permission and fails like any other status.
func limitWait(resp *http.Response, body []byte, now time.Time, attempt int) (time.Duration, bool) {
	h := resp.Header
	exhausted := h.Get("X-RateLimit-Remaining") == "0"
	if resp.StatusCode != http.StatusTooManyRequests && (resp.StatusCode != http.StatusForbidden ||
		h.Get("Retry-After") == "" && !exhausted && !bytes.Contains(body, []byte("rate limit"))) {
		return 0, false
	}
	// 32 bits of seconds cannot overflow a Duration.
	if s, err := strconv.ParseUint(h.Get("Retry-After"), 10, 32); err == nil {
		return time.Duration(s) * time.Second, true
	}
	if reset, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); exhausted && err == nil {
		return max(time.Unix(reset, 0).Sub(now), 0), true
	}
	return time.Minute << attempt, true
}

// do sends one request for get.
func (c *Client) do(ctx context.Context, u, etag string, attempt int) (response, error) {
	tok, err := c.Token(ctx)
	if err != nil {
		return response{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return response{}, fmt.Errorf("github: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return response{}, fmt.Errorf("github: get: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPage+1))
	if err != nil || len(body) > maxPage {
		return response{}, errors.New("github: response too large or unreadable")
	}
	if resp.StatusCode == http.StatusNotModified && etag != "" {
		return response{notModified: true}, nil
	}
	if wait, ok := limitWait(resp, body, c.Now(), attempt); ok {
		return response{}, &rateLimited{req.URL.Path, wait}
	}
	if resp.StatusCode != http.StatusOK {
		return response{}, fmt.Errorf("github: %s: status %d", req.URL.Path, resp.StatusCode)
	}
	return response{body: body, link: resp.Header.Get("Link"), etag: resp.Header.Get("ETag")}, nil
}

// nextLink returns the rel="next" URL of a Link header, or "".
func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		target, params, ok := strings.Cut(strings.TrimSpace(part), ";")
		if !ok || !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		for _, p := range strings.Split(params, ";") {
			if strings.TrimSpace(p) == `rel="next"` {
				return target[1 : len(target)-1]
			}
		}
	}
	return ""
}
