package config

import (
	"errors"
	"strings"
	"testing"
)

func env(m map[string]string) Getenv { return func(k string) string { return m[k] } }

// goodHex is a valid 32-byte key that is not a single repeated byte.
const goodHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func files(m map[string]string) ReadFile {
	return func(p string) ([]byte, error) {
		v, ok := m[p]
		if !ok {
			return nil, errors.New("no such file")
		}
		return []byte(v), nil
	}
}

func prod() map[string]string {
	return map[string]string{
		"NARAEN_TOKEN_KEYS_FILE":   "keys",
		"NARAEN_SSH_HOST_KEY_FILE": "host",
		"NARAEN_TLS_CERT_FILE":     "cert",
		"NARAEN_TLS_KEY_FILE":      "key",
		"NARAEN_PUBLIC_URL":        "https://lfs.example.com",
		"NARAEN_OTLP_ENDPOINT":     "https://otel.example.com",
		"NARAEN_S3_BUCKET":         "acme-lfs",
	}
}

var keyFile = files(map[string]string{"keys": "k1 " + goodHex + "\n"})

func TestLoad(t *testing.T) {
	c, err := Load(env(prod()), keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if c.SSHAddr != ":22" || c.HTTPSAddr != ":443" || c.TokenTTL.Minutes() != 15 || c.Dev {
		t.Errorf("defaults wrong: %+v", c)
	}
	if len(c.TokenKeys) != 1 || c.TokenKeys[0].ID != "k1" || len(c.TokenKeys[0].Secret) != 32 {
		t.Errorf("token keys = %+v", c.TokenKeys)
	}
	if c.SSHHostKeyFile != "host" || c.TLSCertFile != "cert" || c.TLSKeyFile != "key" {
		t.Errorf("key material paths = %+v", c)
	}
	e := prod()
	e["NARAEN_SSH_ADDR"], e["NARAEN_HTTPS_ADDR"] = ":2222", ":8443"
	c, err = Load(env(e), keyFile)
	if err != nil || c.SSHAddr != ":2222" || c.HTTPSAddr != ":8443" {
		t.Errorf("overrides wrong: %+v, %v", c, err)
	}
}

func TestLoadDev(t *testing.T) {
	for _, v := range []string{"", "false"} {
		if _, err := Load(env(map[string]string{"NARAEN_DEV": v}), keyFile); err == nil {
			t.Errorf("NARAEN_DEV=%q started without key material", v)
		}
	}
	c, err := Load(env(map[string]string{"NARAEN_DEV": "true"}), keyFile)
	if err != nil || !c.Dev || c.TokenKeys != nil {
		t.Fatalf("dev = %+v, %v", c, err)
	}
	if _, err := Load(env(map[string]string{"NARAEN_DEV": "yes"}), keyFile); err == nil {
		t.Error("NARAEN_DEV=yes accepted")
	}
	// Each piece of production key material is required on its own.
	for _, missing := range []string{"NARAEN_TOKEN_KEYS_FILE", "NARAEN_SSH_HOST_KEY_FILE"} {
		e := prod()
		delete(e, missing)
		if _, err := Load(env(e), keyFile); err == nil {
			t.Errorf("started without %s", missing)
		}
	}
	e := prod()
	delete(e, "NARAEN_TLS_CERT_FILE")
	delete(e, "NARAEN_TLS_KEY_FILE")
	if _, err := Load(env(e), keyFile); err == nil {
		t.Error("started without TLS files")
	}
}

func TestLoadRejectsHalfTLSPair(t *testing.T) {
	for _, drop := range []string{"NARAEN_TLS_CERT_FILE", "NARAEN_TLS_KEY_FILE"} {
		e := prod()
		e["NARAEN_DEV"] = "true"
		delete(e, drop)
		if _, err := Load(env(e), keyFile); err == nil {
			t.Errorf("accepted without %s", drop)
		}
	}
}

func TestLoadTokenKeys(t *testing.T) {
	other := "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	c, err := Load(env(prod()), files(map[string]string{"keys": "\n  new " + other + "  \n\nold " + goodHex}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TokenKeys) != 2 || c.TokenKeys[0].ID != "new" || c.TokenKeys[1].ID != "old" {
		t.Fatalf("keys = %+v", c.TokenKeys)
	}
	for name, content := range map[string]string{
		"empty":       "",
		"no id":       goodHex,
		"not hex":     "k1 " + strings.Repeat("zz", 32),
		"too short":   "k1 " + goodHex[:62],
		"all zero":    "k1 " + strings.Repeat("00", 32),
		"bad id":      "K.1 " + goodHex,
		"repeated id": "k1 " + goodHex + "\nk1 " + other,
	} {
		if _, err := Load(env(prod()), files(map[string]string{"keys": content})); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The error names the offending line, counting blank lines, from 1.
	_, err = Load(env(prod()), files(map[string]string{"keys": "k1 " + goodHex + "\n\nbroken"}))
	if err == nil || !strings.Contains(err.Error(), "line 3 ") {
		t.Errorf("error for line 3 = %v", err)
	}
	e := prod()
	e["NARAEN_TOKEN_KEYS_FILE"] = "missing"
	if _, err := Load(env(e), keyFile); err == nil {
		t.Error("missing key file accepted")
	}
}

func TestPublicURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://lfs.example.com":      "https://lfs.example.com",
		"https://lfs.example.com/":     "https://lfs.example.com",
		"https://lfs.example.com:8443": "https://lfs.example.com:8443",
		"https://[2001:db8::1]:8443/":  "https://[2001:db8::1]:8443",
		"https://LFS.example.com:443/": "https://LFS.example.com:443",
		"https://127.0.0.1:12345":      "https://127.0.0.1:12345",
	} {
		e := prod()
		e["NARAEN_PUBLIC_URL"] = in
		c, err := Load(env(e), keyFile)
		if err != nil || c.PublicURL != want {
			t.Errorf("%q: got %q, %v; want %q", in, c.PublicURL, err, want)
		}
	}
	for _, bad := range []string{
		"https://[::1",                // unparseable
		"http://lfs.example.com",      // not TLS
		"lfs.example.com",             // no scheme
		"https://",                    // no host
		"https://:443",                // port but no host
		"https://u:p@lfs.example.com", // userinfo
		"https://lfs.example.com/lfs", // a path
		"https://lfs.example.com?a=b", // a query
		"https://lfs.example.com?",    // an empty query
		"https://lfs.example.com#top", // a fragment
	} {
		e := prod()
		e["NARAEN_PUBLIC_URL"] = bad
		if _, err := Load(env(e), keyFile); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	e := prod()
	delete(e, "NARAEN_PUBLIC_URL")
	if _, err := Load(env(e), keyFile); err == nil {
		t.Error("started without NARAEN_PUBLIC_URL outside dev mode")
	}
	// Dev mode defaults to localhost on the HTTPS listen port.
	for addr, want := range map[string]string{
		"":               "https://localhost:443",
		":8443":          "https://localhost:8443",
		"127.0.0.1:2443": "https://localhost:2443",
	} {
		c, err := Load(env(map[string]string{"NARAEN_DEV": "true", "NARAEN_HTTPS_ADDR": addr}), keyFile)
		if err != nil || c.PublicURL != want {
			t.Errorf("dev default for %q = %q, %v; want %q", addr, c.PublicURL, err, want)
		}
	}
	if _, err := Load(env(map[string]string{"NARAEN_DEV": "true", "NARAEN_HTTPS_ADDR": "no-port"}), keyFile); err == nil {
		t.Error("dev default from an address without a port accepted")
	}
}

func TestSnapshotMaxAge(t *testing.T) {
	base := prod()
	base["NARAEN_SNAPSHOT_MAX_AGE"] = "90m"
	c, err := Load(env(base), keyFile)
	if err != nil || c.SnapshotMaxAge.Minutes() != 90 {
		t.Errorf("max age = %v, %v", c.SnapshotMaxAge, err)
	}
	for _, bad := range []string{"soon", "0s", "-1h"} {
		base["NARAEN_SNAPSHOT_MAX_AGE"] = bad
		if _, err := Load(env(base), keyFile); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSSHConnRate(t *testing.T) {
	c, err := Load(env(prod()), keyFile)
	if err != nil || c.SSHConnBurst != 0 || c.SSHConnInterval != 0 {
		t.Errorf("unset rate overrides = %d, %v, %v", c.SSHConnBurst, c.SSHConnInterval, err)
	}
	base := prod()
	base["NARAEN_SSH_CONN_BURST"], base["NARAEN_SSH_CONN_INTERVAL"] = "1", "10ms"
	c, err = Load(env(base), keyFile)
	if err != nil || c.SSHConnBurst != 1 || c.SSHConnInterval.Milliseconds() != 10 {
		t.Errorf("rate overrides = %d, %v, %v", c.SSHConnBurst, c.SSHConnInterval, err)
	}
	for _, bad := range []string{"many", "0", "-1", "1.5"} {
		e := prod()
		e["NARAEN_SSH_CONN_BURST"] = bad
		if _, err := Load(env(e), keyFile); err == nil {
			t.Errorf("burst %q accepted", bad)
		}
	}
	for _, bad := range []string{"often", "0s", "-1s"} {
		e := prod()
		e["NARAEN_SSH_CONN_INTERVAL"] = bad
		if _, err := Load(env(e), keyFile); err == nil {
			t.Errorf("interval %q accepted", bad)
		}
	}
}

func TestOTLPEndpoint(t *testing.T) {
	for good, want := range map[string]string{
		"https://otel.example.com":                      "https://otel.example.com",
		"https://otel.example.com/":                     "https://otel.example.com",
		"https://openobserve.internal:5080/api/default": "https://openobserve.internal:5080/api/default",
		"http://localhost:4318":                         "http://localhost:4318",
		"http://127.0.0.1:4318/":                        "http://127.0.0.1:4318",
		"http://127.0.0.9:4318":                         "http://127.0.0.9:4318",
		"http://[::1]:4318":                             "http://[::1]:4318",
	} {
		e := prod()
		e["NARAEN_OTLP_ENDPOINT"] = good
		c, err := Load(env(e), keyFile)
		if err != nil || c.OTLPEndpoint != want {
			t.Errorf("%q: got %q, %v; want %q", good, c.OTLPEndpoint, err, want)
		}
	}
	for _, bad := range []string{
		"https://[::1",                        // unparseable
		"http://otel.example.com/v1/metrics",  // cleartext over the network
		"http://10.0.0.5:4318/v1/metrics",     // cleartext, not loopback
		"ftp://localhost/v1/metrics",          // not HTTP
		"otel.example.com/v1/metrics",         // no scheme
		"https:///v1/metrics",                 // no host
		"https://u:p@otel.example.com/",       // userinfo
		"https://otel.example.com/v1#metrics", // a fragment
	} {
		e := prod()
		e["NARAEN_OTLP_ENDPOINT"] = bad
		if _, err := Load(env(e), keyFile); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	e := prod()
	delete(e, "NARAEN_OTLP_ENDPOINT")
	c, err := Load(env(e), keyFile)
	if err != nil || c.OTLPEndpoint != "" {
		t.Errorf("no endpoint = %q, %v; want no export", c.OTLPEndpoint, err)
	}
}

func TestOTLPHeaders(t *testing.T) {
	e := prod()
	e["NARAEN_OTLP_HEADERS_FILE"] = "headers"
	// Az-Z09 holds every boundary byte of the accepted ranges.
	c, err := Load(env(e), files(map[string]string{
		"keys":    "k1 " + goodHex,
		"headers": "\n Authorization:  Basic c2VjcmV0 \n\nX-Stream-0: a:b\nAz-Z09: c\n",
	}))
	if err != nil || len(c.OTLPHeaders) != 3 || c.OTLPHeaders["Authorization"] != "Basic c2VjcmV0" ||
		c.OTLPHeaders["X-Stream-0"] != "a:b" || c.OTLPHeaders["Az-Z09"] != "c" {
		t.Fatalf("headers = %q, %v", c.OTLPHeaders, err)
	}
	if c, err := Load(env(prod()), keyFile); err != nil || c.OTLPHeaders != nil {
		t.Errorf("no headers file = %q, %v", c.OTLPHeaders, err)
	}
	for name, content := range map[string]string{
		"no colon":      "Authorization Basic x",
		"no value":      "Authorization:",
		"blank value":   "Authorization:   ",
		"no name":       ": x",
		"space in name": "X Auth: x",
		"bad byte":      "X_Auth: x",
		"below digits":  "X/Auth: x",
		"above lower":   "X{Auth: x",
		"above upper":   "X[Auth: x",
		"below upper":   "X@Auth: x",
		"above digits":  "X;Auth: x",
		"below lower":   "X`Auth: x",
	} {
		_, err := Load(env(e), files(map[string]string{"keys": "k1 " + goodHex, "headers": content}))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), content) {
			t.Errorf("%s: error echoes the line: %v", name, err)
		}
	}
	_, err = Load(env(e), files(map[string]string{"keys": "k1 " + goodHex, "headers": "A: 1\n\nbroken"}))
	if err == nil || !strings.Contains(err.Error(), "line 3 ") {
		t.Errorf("error for line 3 = %v", err)
	}
	e["NARAEN_OTLP_HEADERS_FILE"] = "missing"
	if _, err := Load(env(e), keyFile); err == nil {
		t.Error("missing headers file accepted")
	}
}

func TestBucket(t *testing.T) {
	c, err := Load(env(prod()), keyFile)
	if err != nil || c.Bucket != "acme-lfs" {
		t.Fatalf("bucket = %q, %v", c.Bucket, err)
	}
	e := prod()
	e["NARAEN_S3_BUCKET"] = strings.Repeat("b", 63)
	if _, err := Load(env(e), keyFile); err != nil {
		t.Errorf("longest name: %v", err)
	}
	e["NARAEN_S3_BUCKET"] = "a-9"
	if c, err := Load(env(e), keyFile); err != nil || c.Bucket != "a-9" {
		t.Errorf("shortest name: %q, %v", c.Bucket, err)
	}
	for name, bucket := range map[string]string{
		"too short":      "ab",
		"too long":       strings.Repeat("b", 64),
		"leading hyphen": "-abc",
		"trailing hyph":  "abc-",
		"upper case":     "Abc",
		"dot":            "a.bc",
		"underscore":     "a_bc",
		"below digits":   "a/bc",
		"above digits":   "a:bc",
		"below lower":    "a`bc",
		"above lower":    "a{bc",
	} {
		e["NARAEN_S3_BUCKET"] = bucket
		if _, err := Load(env(e), keyFile); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	delete(e, "NARAEN_S3_BUCKET")
	if _, err := Load(env(e), keyFile); err == nil {
		t.Error("started without a bucket outside dev mode")
	}
	if c, err := Load(env(map[string]string{"NARAEN_DEV": "true"}), keyFile); err != nil || c.Bucket != "" {
		t.Errorf("dev without a bucket = %q, %v", c.Bucket, err)
	}
}

func TestS3Endpoint(t *testing.T) {
	e := prod()
	e["NARAEN_S3_ENDPOINT"] = "http://127.0.0.1:8333/"
	if c, err := Load(env(e), keyFile); err != nil || c.S3Endpoint != "http://127.0.0.1:8333" {
		t.Errorf("endpoint = %q, %v", c.S3Endpoint, err)
	}
	e["NARAEN_S3_ENDPOINT"] = "http://s3.example.com"
	if _, err := Load(env(e), keyFile); err == nil || !strings.Contains(err.Error(), "NARAEN_S3_ENDPOINT") {
		t.Errorf("cleartext endpoint over the network: %v", err)
	}
	if c, err := Load(env(prod()), keyFile); err != nil || c.S3Endpoint != "" {
		t.Errorf("default = %q, %v", c.S3Endpoint, err)
	}
}
