// Package token mints and verifies the short-lived bearer tokens returned by
// git-lfs-authenticate. A token is bound to one identity, one repo ID and one
// operation, and expires quickly.
//
// The format is "v1.<key id>.<payload>.<mac>". The key ID lets a new key take
// over minting while tokens signed with the previous one still verify, and the
// MAC covers a domain string as well as the key ID and payload, so the same
// key can never validate a token of some other type or version.
package token

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rurounijones/naraen/internal/lfs"
)

const (
	// MinKeyLength is the minimum HMAC key size in bytes.
	MinKeyLength = 32
	// maxTokenLength bounds untrusted input before any decoding.
	maxTokenLength = 1024
	// maxKeyIDLength bounds key IDs, which travel in every token.
	maxKeyIDLength = 16

	version = "v1"
	// domain separates these MACs from any other use of the same key.
	domain = "naraen lfs bearer token v1\x00"
)

// ErrInvalid is returned for every verification failure. It carries no detail.
var ErrInvalid = errors.New("token: invalid")

// Strict rejects non-canonical encodings, so a token has exactly one valid form.
var enc = base64.RawURLEncoding.Strict()

// Claims is the signed payload.
type Claims struct {
	Subject string        `json:"sub"`
	RepoID  string        `json:"rid"`
	Op      lfs.Operation `json:"op"`
	Expires int64         `json:"exp"`
}

// Key is one HMAC key and the ID that names it in tokens.
type Key struct {
	ID     string
	Secret []byte
}

// Signer mints with its first key and verifies with any of its keys.
type Signer struct {
	keys []Key
	ttl  time.Duration
	// Now is replaceable in tests.
	Now func() time.Time
}

// NewSigner returns a Signer. keys[0] mints; every key verifies, so a rotated
// key can stay listed until the tokens it signed have expired. Each key must
// be at least MinKeyLength bytes and not a single repeated byte (such as all
// zeroes), and IDs must be unique, short, lowercase alphanumeric or '-'.
func NewSigner(keys []Key, ttl time.Duration) (*Signer, error) {
	if len(keys) == 0 {
		return nil, errors.New("token: at least one key is required")
	}
	if ttl <= 0 {
		return nil, errors.New("token: ttl must be positive")
	}
	s := &Signer{ttl: ttl, Now: time.Now}
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if !validKeyID(k.ID) || seen[k.ID] {
			return nil, fmt.Errorf("token: key ID %q is malformed or repeated", k.ID)
		}
		seen[k.ID] = true
		if len(k.Secret) < MinKeyLength {
			return nil, fmt.Errorf("token: key %q must be at least %d bytes", k.ID, MinKeyLength)
		}
		if oneRepeatedByte(k.Secret) {
			return nil, fmt.Errorf("token: key %q is a single repeated byte", k.ID)
		}
		s.keys = append(s.keys, Key{ID: k.ID, Secret: append([]byte(nil), k.Secret...)})
	}
	return s, nil
}

// oneRepeatedByte reports whether every byte of b equals the first. It
// compares counts, not key material, so it need not be constant time.
func oneRepeatedByte(b []byte) bool { return bytes.Count(b, b[:1]) == len(b) }

func validKeyID(id string) bool {
	if id == "" || len(id) > maxKeyIDLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// TTL returns the lifetime of minted tokens.
func (s *Signer) TTL() time.Duration { return s.ttl }

// Mint returns a token for subject, repoID and op, signed with the first key.
func (s *Signer) Mint(subject, repoID string, op lfs.Operation) (string, error) {
	c := Claims{Subject: subject, RepoID: repoID, Op: op, Expires: s.Now().Add(s.ttl).Unix()}
	// Claims holds only strings and integers, so Marshal cannot fail.
	payload, _ := json.Marshal(c)
	k := s.keys[0]
	p := enc.EncodeToString(payload)
	return version + "." + k.ID + "." + p + "." + enc.EncodeToString(mac(k, p)), nil
}

// Verify checks version, key, signature, expiry, and that the token was
// issued for exactly repoID and op.
func (s *Signer) Verify(tok, repoID string, op lfs.Operation) (Claims, error) {
	if len(tok) == 0 || len(tok) > maxTokenLength {
		return Claims{}, ErrInvalid
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 4 || parts[0] != version {
		return Claims{}, ErrInvalid
	}
	k, ok := s.key(parts[1])
	if !ok {
		return Claims{}, ErrInvalid
	}
	p := parts[2]
	got, err := enc.DecodeString(parts[3])
	if err != nil || !hmac.Equal(got, mac(k, p)) {
		return Claims{}, ErrInvalid
	}
	raw, err := enc.DecodeString(p)
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return Claims{}, ErrInvalid
	}
	if c.Subject == "" || !s.Now().Before(time.Unix(c.Expires, 0)) {
		return Claims{}, ErrInvalid
	}
	if c.RepoID != repoID || c.Op != op {
		return Claims{}, ErrInvalid
	}
	return c, nil
}

func (s *Signer) key(id string) (Key, bool) {
	for _, k := range s.keys {
		if k.ID == id {
			return k, true
		}
	}
	return Key{}, false
}

func mac(k Key, payload string) []byte {
	m := hmac.New(sha256.New, k.Secret)
	m.Write([]byte(domain + k.ID + "." + payload))
	return m.Sum(nil)
}
