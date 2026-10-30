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
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
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
	if len(a.token) > 0 && now.Add(tokenRefresh).Before(a.expires) {
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
}

// pages fetches path and every following page named by the Link header,
// passing each body to fn. A next link must stay on BaseURL, so a response
// cannot send the installation token anywhere else.
func (c *Client) pages(ctx context.Context, path string, fn func(io.Reader) error) error {
	next := c.BaseURL + path
	for range maxPages {
		body, link, err := c.get(ctx, next)
		if err != nil {
			return err
		}
		if err := fn(bytes.NewReader(body)); err != nil {
			return fmt.Errorf("github: %s: %w", path, err)
		}
		next = nextLink(link)
		if next == "" {
			return nil
		}
		if !strings.HasPrefix(next, c.BaseURL+"/") {
			return fmt.Errorf("github: %s: next page outside the API: %q", path, next)
		}
	}
	return fmt.Errorf("github: %s: more than %d pages", path, maxPages)
}

func (c *Client) get(ctx context.Context, u string) ([]byte, string, error) {
	tok, err := c.Token(ctx)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", fmt.Errorf("github: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("github: get: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPage+1))
	if err != nil || len(body) > maxPage {
		return nil, "", errors.New("github: response too large or unreadable")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("github: %s: status %d", req.URL.Path, resp.StatusCode)
	}
	return body, resp.Header.Get("Link"), nil
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
