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
