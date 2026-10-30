// Package config loads server configuration from the environment. Secrets are
// never taken from environment variables, which leak through /proc, crash
// reports and container inspection; the environment only names the files
// that hold them (written from SSM Parameter Store in production).
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rurounijones/naraen/internal/token"
)

// Config is the validated server configuration.
type Config struct {
	SSHAddr   string
	HTTPSAddr string
	// PublicURL is the HTTPS origin clients reach the Batch API at, such as
	// https://lfs.example.com, with no trailing slash. git-lfs-authenticate
	// returns it, so it must be the name clients use, which the listen address
	// does not tell.
	PublicURL string
	// Dev allows ephemeral key material (token key, SSH host key, TLS
	// certificate) for anything not configured. Without it, all three are
	// required, so a production server cannot start on throwaway keys.
	Dev bool
	// TokenKeys holds the token signing keys, the first of which mints. It is
	// empty only in dev mode with no key file.
	TokenKeys      []token.Key
	TokenTTL       time.Duration
	SSHHostKeyFile string
	TLSCertFile    string
	TLSKeyFile     string
	SnapshotFile   string // dev/test: load the datastore from a file instead of a provider
	SnapshotMaxAge time.Duration
	// SSHConnBurst and SSHConnInterval override the per-source SSH connection
	// rate limit, for deployments where many clients share one address (an
	// office NAT or CI egress). Zero keeps the server's default.
	SSHConnBurst    int
	SSHConnInterval time.Duration
	// OTLPEndpoint is the OTLP/HTTP base URL, such as
	// https://openobserve.internal:5080/api/default, without a trailing
	// slash; metrics and logs go to /v1/metrics and /v1/logs under it.
	// Optional; empty means metrics are recorded but not exported, and logs
	// go to stdout only.
	OTLPEndpoint string
	// OTLPHeaders are sent with every export, typically the ingestion
	// credential, so they come from a file, never the environment.
	OTLPHeaders map[string]string
	// Bucket is the S3 bucket holding every repo's objects, each repo under a
	// top-level folder named by its ID. It is required unless Dev.
	Bucket string
	// S3Endpoint replaces the AWS S3 endpoint, for S3-compatible storage such
	// as SeaweedFS in development and tests. Empty means AWS.
	S3Endpoint string
	// GitHub configures the GitHub provider. Nil means no provider: the
	// datastore comes from SnapshotFile, if anything.
	GitHub *GitHub
	// WebhookSecret verifies GitHub webhook deliveries. Empty means the
	// webhook endpoint is not served and access changes wait for the next
	// full sync.
	WebhookSecret []byte
}

// GitHub is the GitHub provider's configuration.
type GitHub struct {
	Org            string
	AppID          string
	InstallationID string
	// AppKey is the App's private key, PEM encoded: the provider's only
	// credential.
	AppKey []byte
	// APIURL is the REST API's base URL; JWKSURL is where GitHub Actions'
	// OIDC keys are fetched. Both are overridden only for tests and GitHub
	// Enterprise.
	APIURL  string
	JWKSURL string
	// Audience is the custom audience CI jobs request OIDC tokens for. Empty
	// means CI token exchange is not set up.
	Audience     string
	SyncInterval time.Duration
}

// Getenv abstracts os.Getenv for tests.
type Getenv func(string) string

// ReadFile abstracts os.ReadFile for tests.
type ReadFile func(string) ([]byte, error)

// Load reads configuration using getenv, and the token key file using readFile.
func Load(getenv Getenv, readFile ReadFile) (Config, error) {
	c := Config{
		SSHAddr:        or(getenv("NARAEN_SSH_ADDR"), ":22"),
		HTTPSAddr:      or(getenv("NARAEN_HTTPS_ADDR"), ":443"),
		SSHHostKeyFile: getenv("NARAEN_SSH_HOST_KEY_FILE"),
		TLSCertFile:    getenv("NARAEN_TLS_CERT_FILE"),
		TLSKeyFile:     getenv("NARAEN_TLS_KEY_FILE"),
		SnapshotFile:   getenv("NARAEN_SNAPSHOT_FILE"),
		TokenTTL:       15 * time.Minute,
		SnapshotMaxAge: time.Hour,
	}
	switch v := getenv("NARAEN_DEV"); v {
	case "", "false":
	case "true":
		c.Dev = true
	default:
		return Config{}, fmt.Errorf("config: NARAEN_DEV must be true or false: %q", v)
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return Config{}, errors.New("config: NARAEN_TLS_CERT_FILE and NARAEN_TLS_KEY_FILE must be set together")
	}
	if path := getenv("NARAEN_TOKEN_KEYS_FILE"); path != "" {
		raw, err := readFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: token keys: %w", err)
		}
		if c.TokenKeys, err = parseKeys(string(raw)); err != nil {
			return Config{}, err
		}
	}
	if !c.Dev && (len(c.TokenKeys) == 0 || c.SSHHostKeyFile == "" || c.TLSCertFile == "") {
		return Config{}, errors.New("config: NARAEN_TOKEN_KEYS_FILE, NARAEN_SSH_HOST_KEY_FILE and the TLS files are required unless NARAEN_DEV=true")
	}
	var err error
	if c.PublicURL, err = publicURL(getenv("NARAEN_PUBLIC_URL"), c.HTTPSAddr, c.Dev); err != nil {
		return Config{}, err
	}
	if v := getenv("NARAEN_SNAPSHOT_MAX_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("config: NARAEN_SNAPSHOT_MAX_AGE must be a positive duration: %q", v)
		}
		c.SnapshotMaxAge = d
	}
	if v := getenv("NARAEN_SSH_CONN_BURST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("config: NARAEN_SSH_CONN_BURST must be a positive integer: %q", v)
		}
		c.SSHConnBurst = n
	}
	if v := getenv("NARAEN_SSH_CONN_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("config: NARAEN_SSH_CONN_INTERVAL must be a positive duration: %q", v)
		}
		c.SSHConnInterval = d
	}
	if c.OTLPEndpoint, err = endpoint("NARAEN_OTLP_ENDPOINT", getenv("NARAEN_OTLP_ENDPOINT")); err != nil {
		return Config{}, err
	}
	if path := getenv("NARAEN_OTLP_HEADERS_FILE"); path != "" {
		raw, err := readFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: otlp headers: %w", err)
		}
		if c.OTLPHeaders, err = parseHeaders(string(raw)); err != nil {
			return Config{}, err
		}
	}
	if c.S3Endpoint, err = endpoint("NARAEN_S3_ENDPOINT", getenv("NARAEN_S3_ENDPOINT")); err != nil {
		return Config{}, err
	}
	if c.Bucket = getenv("NARAEN_S3_BUCKET"); c.Bucket != "" && !bucketName(c.Bucket) {
		return Config{}, fmt.Errorf("config: NARAEN_S3_BUCKET must be an S3 bucket name without dots: %q", c.Bucket)
	}
	if path := getenv("NARAEN_GITHUB_WEBHOOK_SECRET_FILE"); path != "" {
		raw, err := readFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: webhook secret: %w", err)
		}
		if c.WebhookSecret = []byte(strings.TrimSpace(string(raw))); len(c.WebhookSecret) < minWebhookSecret {
			return Config{}, fmt.Errorf("config: webhook secret must be at least %d bytes", minWebhookSecret)
		}
	}
	if c.GitHub, err = loadGitHub(getenv, readFile); err != nil {
		return Config{}, err
	}
	if c.GitHub != nil && c.SnapshotFile != "" {
		return Config{}, errors.New("config: NARAEN_SNAPSHOT_FILE and the GitHub provider are alternatives; set one")
	}
	if !c.Dev && c.Bucket == "" {
		return Config{}, errors.New("config: NARAEN_S3_BUCKET is required unless NARAEN_DEV=true")
	}
	return c, nil
}

// loadGitHub reads the GitHub provider settings. Org, App ID, installation ID
// and key file are all or nothing, so a half-configured provider fails at
// startup instead of syncing nothing.
func loadGitHub(getenv Getenv, readFile ReadFile) (*GitHub, error) {
	g := &GitHub{
		Org:            getenv("NARAEN_GITHUB_ORG"),
		AppID:          getenv("NARAEN_GITHUB_APP_ID"),
		InstallationID: getenv("NARAEN_GITHUB_INSTALLATION_ID"),
		Audience:       getenv("NARAEN_OIDC_AUDIENCE"),
		SyncInterval:   15 * time.Minute,
	}
	keyFile := getenv("NARAEN_GITHUB_APP_KEY_FILE")
	set := 0
	for _, v := range []string{g.Org, g.AppID, g.InstallationID, keyFile} {
		if v != "" {
			set++
		}
	}
	if set == 0 {
		return nil, nil
	}
	if set != 4 {
		return nil, errors.New("config: NARAEN_GITHUB_ORG, NARAEN_GITHUB_APP_ID, NARAEN_GITHUB_INSTALLATION_ID and NARAEN_GITHUB_APP_KEY_FILE must be set together")
	}
	raw, err := readFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("config: github app key: %w", err)
	}
	g.AppKey = raw
	if g.APIURL, err = endpoint("NARAEN_GITHUB_API_URL", or(getenv("NARAEN_GITHUB_API_URL"), "https://api.github.com")); err != nil {
		return nil, err
	}
	jwks := or(getenv("NARAEN_GITHUB_JWKS_URL"), "https://token.actions.githubusercontent.com/.well-known/jwks")
	if g.JWKSURL, err = endpoint("NARAEN_GITHUB_JWKS_URL", jwks); err != nil {
		return nil, err
	}
	if v := getenv("NARAEN_SYNC_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			return nil, fmt.Errorf("config: NARAEN_SYNC_INTERVAL must be a duration of at least 1m: %q", v)
		}
		g.SyncInterval = d
	}
	return g, nil
}

// minWebhookSecret is the shortest webhook secret accepted. GitHub accepts
// any length; a short one would let a forged delivery be brute-forced.
const minWebhookSecret = 20

// bucketName accepts S3 bucket names without dots: 3 to 63 lowercase letters,
// digits and hyphens, starting and ending with a letter or digit. Dots are
// legal in S3 but break TLS for virtual-hosted URLs, so they are refused.
func bucketName(s string) bool {
	if len(s) < 3 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// endpoint validates the URL of a service the server calls, named by the
// variable name. Traffic to it carries credentials (the OTLP ingestion
// credential, S3 request signatures) and names users and repos, so it goes
// over https, except to a loopback address, where a local collector, a
// development S3 or a test receiver listens and nothing crosses the network.
// Empty means the default: no export, or AWS.
func endpoint(name, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" ||
		(u.Scheme != "https" && (u.Scheme != "http" || !loopback(u.Hostname()))) {
		return "", fmt.Errorf("config: %s must be an https URL, or http to a loopback address: %q", name, v)
	}
	return strings.TrimSuffix(v, "/"), nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// parseHeaders reads one "Name: value" header per non-empty line.
func parseHeaders(s string) (map[string]string, error) {
	h := map[string]string{}
	for n, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		if !ok || !headerName(name) || value == "" {
			// The line may hold a credential, so it is not echoed.
			return nil, fmt.Errorf("config: otlp headers line %d must be \"Name: value\"", n+1)
		}
		h[name] = value
	}
	return h, nil
}

// headerName accepts the letters, digits and hyphens that real header names
// use, a subset of RFC 9110's token.
func headerName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// parseKeys reads one "<id> <hex secret>" pair per non-empty line. The first
// line is the minting key; later lines verify only, so a rotated key stays
// listed until its tokens have expired. Key rules are enforced by
// token.NewSigner, which is called here so that a bad file fails at startup.
func parseKeys(s string) ([]token.Key, error) {
	var keys []token.Key
	for n, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		id, h, ok := strings.Cut(line, " ")
		secret, err := hex.DecodeString(h)
		if !ok || err != nil {
			return nil, fmt.Errorf("config: token keys line %d must be \"<id> <hex>\"", n+1)
		}
		keys = append(keys, token.Key{ID: id, Secret: secret})
	}
	if _, err := token.NewSigner(keys, time.Minute); err != nil {
		return nil, fmt.Errorf("config: token keys: %w", err)
	}
	return keys, nil
}

// publicURL validates NARAEN_PUBLIC_URL: an https origin and nothing else, so
// the repo path appended to it cannot be redirected by a stray path, query,
// fragment or userinfo. In dev mode it defaults to localhost on the HTTPS
// listen port, which is where a local client reaches a local server.
func publicURL(v, httpsAddr string, dev bool) (string, error) {
	if v == "" {
		if !dev {
			return "", errors.New("config: NARAEN_PUBLIC_URL is required unless NARAEN_DEV=true")
		}
		_, port, err := net.SplitHostPort(httpsAddr)
		if err != nil {
			return "", fmt.Errorf("config: NARAEN_HTTPS_ADDR: %w", err)
		}
		return "https://" + net.JoinHostPort("localhost", port), nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("config: NARAEN_PUBLIC_URL must be an https origin such as https://lfs.example.com: %q", v)
	}
	return "https://" + u.Host, nil
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
