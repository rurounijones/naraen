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
	return c, nil
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
