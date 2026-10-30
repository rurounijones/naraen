package token

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rurounijones/naraen/internal/lfs"
)

var t0 = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// secret returns a valid key of MinKeyLength bytes that differs per seed.
func secret(seed byte) []byte {
	b := make([]byte, MinKeyLength)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

var key = Key{ID: "k1", Secret: secret(7)}

func newSigner(t *testing.T, keys ...Key) *Signer {
	t.Helper()
	if len(keys) == 0 {
		keys = []Key{key}
	}
	s, err := NewSigner(keys, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return t0 }
	return s
}

func TestNewSignerValidation(t *testing.T) {
	tests := map[string][]Key{
		"no keys":         nil,
		"short key":       {{ID: "k", Secret: secret(1)[:MinKeyLength-1]}},
		"all zero key":    {{ID: "k", Secret: make([]byte, MinKeyLength)}},
		"repeated byte":   {{ID: "k", Secret: bytes.Repeat([]byte{7}, 64)}},
		"empty id":        {{ID: "", Secret: secret(1)}},
		"long id":         {{ID: strings.Repeat("a", maxKeyIDLength+1), Secret: secret(1)}},
		"id with dot":     {{ID: "a.b", Secret: secret(1)}},
		"uppercase id":    {{ID: "K", Secret: secret(1)}},
		"id below digits": {{ID: "/", Secret: secret(1)}},
		"id above lower":  {{ID: "{", Secret: secret(1)}},
		"duplicate id":    {{ID: "k", Secret: secret(1)}, {ID: "k", Secret: secret(2)}},
	}
	for name, keys := range tests {
		if _, err := NewSigner(keys, time.Minute); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewSigner([]Key{key}, 0); err == nil {
		t.Error("zero ttl accepted")
	}
	s, err := NewSigner([]Key{{ID: strings.Repeat("z", maxKeyIDLength), Secret: secret(1)}, {ID: "0-9", Secret: secret(2)}}, time.Minute)
	if err != nil || s.TTL() != time.Minute {
		t.Errorf("NewSigner = %v, %v", s, err)
	}
}

func TestRoundTrip(t *testing.T) {
	s := newSigner(t)
	tok, minted, err := s.Mint("alice", "r1", lfs.Download)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "v1.k1.") {
		t.Errorf("token %q lacks version and key ID", tok)
	}
	c, err := s.Verify(tok, "r1", lfs.Download)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "alice" || c.RepoID != "r1" || c.Op != lfs.Download {
		t.Errorf("claims = %+v", c)
	}
	if c != minted || len(c.ID) != 22 || c.Expires != t0.Add(15*time.Minute).Unix() {
		t.Errorf("verified %+v, minted %+v", c, minted)
	}
}

// Two tokens for the same identity, repo and operation in the same second
// still differ, so each can be traced to its own issue record.
func TestTokenIDsAreUnique(t *testing.T) {
	s := newSigner(t)
	a, ca, _ := s.Mint("alice", "r1", lfs.Download)
	b, cb, _ := s.Mint("alice", "r1", lfs.Download)
	if a == b || ca.ID == cb.ID {
		t.Fatalf("identical tokens %q and %q", a, b)
	}
}

func TestMintFailsWithoutRandomness(t *testing.T) {
	s := newSigner(t)
	s.Rand = bytes.NewReader(make([]byte, idBytes-1))
	if tok, c, err := s.Mint("alice", "r1", lfs.Download); err == nil || tok != "" || c != (Claims{}) {
		t.Fatalf("Mint = %q, %+v, %v; want an error and nothing else", tok, c, err)
	}
}

// After rotation, the new key mints and tokens from the old key still verify
// until the old key is removed from the list.
func TestKeyRotation(t *testing.T) {
	old := newSigner(t, key)
	tok, _, _ := old.Mint("alice", "r1", lfs.Download)

	next := Key{ID: "k2", Secret: secret(50)}
	rotated := newSigner(t, next, key)
	if _, err := rotated.Verify(tok, "r1", lfs.Download); err != nil {
		t.Fatalf("token from previous key rejected: %v", err)
	}
	fresh, _, _ := rotated.Mint("alice", "r1", lfs.Download)
	if !strings.HasPrefix(fresh, "v1.k2.") {
		t.Fatalf("rotated signer minted with %q", fresh)
	}
	retired := newSigner(t, next)
	if _, err := retired.Verify(tok, "r1", lfs.Download); !errors.Is(err, ErrInvalid) {
		t.Fatalf("token from removed key accepted: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	s := newSigner(t)
	good, _, _ := s.Mint("alice", "r1", lfs.Download)
	parts := strings.Split(good, ".")
	payload, sig := parts[2], parts[3]
	with := func(i int, v string) string {
		p := append([]string{}, parts...)
		p[i] = v
		return strings.Join(p, ".")
	}

	foreign, _, _ := newSigner(t, Key{ID: "k1", Secret: secret(9)}).Mint("alice", "r1", lfs.Download)
	noSubject, _, _ := s.Mint("", "r1", lfs.Download)

	// A MAC over the bare payload, as an undomained or unversioned scheme
	// would compute it, must not verify.
	m := hmac.New(sha256.New, key.Secret)
	m.Write([]byte(payload))
	undomained := with(3, enc.EncodeToString(m.Sum(nil)))

	tests := []struct {
		name   string
		tok    string
		repoID string
		op     lfs.Operation
	}{
		{"empty", "", "r1", lfs.Download},
		{"three parts", strings.Join(parts[1:], "."), "r1", lfs.Download},
		{"five parts", good + ".x", "r1", lfs.Download},
		{"wrong version", with(0, "v2"), "r1", lfs.Download},
		{"unknown key id", with(1, "k9"), "r1", lfs.Download},
		{"empty signature", with(3, ""), "r1", lfs.Download},
		{"garbage signature", with(3, "!!!"), "r1", lfs.Download},
		{"tampered payload", with(2, payload+"A"), "r1", lfs.Download},
		{"tampered signature", with(3, flip(sig)), "r1", lfs.Download},
		{"non-canonical signature", with(3, sig[:len(sig)-1]+nonCanonical(sig[len(sig)-1])), "r1", lfs.Download},
		{"other key same id", foreign, "r1", lfs.Download},
		{"undomained mac", undomained, "r1", lfs.Download},
		{"wrong repo", good, "r2", lfs.Download},
		{"wrong operation", good, "r1", lfs.Upload},
		{"empty subject", noSubject, "r1", lfs.Download},
		{"oversized", strings.Repeat("a", maxTokenLength+1), "r1", lfs.Download},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.Verify(tt.tok, tt.repoID, tt.op); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

// The key ID is covered by the MAC: relabelling a token to another key the
// verifier holds must fail even if that key had produced the same MAC input.
func TestKeyIDIsSigned(t *testing.T) {
	a, b := Key{ID: "a", Secret: secret(1)}, Key{ID: "b", Secret: secret(1)}
	s := newSigner(t, a, b)
	tok, _, _ := s.Mint("alice", "r1", lfs.Download)
	relabelled := "v1.b." + strings.SplitN(tok, ".", 3)[2]
	if _, err := s.Verify(relabelled, "r1", lfs.Download); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relabelled token accepted: %v", err)
	}
}

// flip changes the first character of s.
func flip(s string) string {
	if s[0] == 'A' {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}

// nonCanonical returns a final base64url character that decodes to the same
// bytes as c under lenient decoding (the 2 trailing bits of a 43-char encoding
// of 32 bytes are padding) but is not the canonical encoding.
func nonCanonical(c byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, c)
	return string(alphabet[i^1])
}

func TestVerifyAcceptsMaximumLength(t *testing.T) {
	s := newSigner(t)
	for n := 1; n < maxTokenLength; n++ {
		tok, _, _ := s.Mint("alice", strings.Repeat("r", n), lfs.Upload)
		if len(tok) < maxTokenLength {
			continue
		}
		if len(tok) != maxTokenLength {
			t.Fatalf("no repo ID length yields exactly %d bytes (got %d)", maxTokenLength, len(tok))
		}
		if _, err := s.Verify(tok, strings.Repeat("r", n), lfs.Upload); err != nil {
			t.Fatalf("token of exactly maxTokenLength rejected: %v", err)
		}
		if _, err := s.Verify(tok+"a", strings.Repeat("r", n), lfs.Upload); !errors.Is(err, ErrInvalid) {
			t.Fatalf("token one byte over: %v", err)
		}
		return
	}
	t.Fatal("never reached maxTokenLength")
}

func TestExpiry(t *testing.T) {
	s := newSigner(t)
	tok, _, _ := s.Mint("alice", "r1", lfs.Upload)

	s.Now = func() time.Time { return t0.Add(15*time.Minute - time.Second) }
	if _, err := s.Verify(tok, "r1", lfs.Upload); err != nil {
		t.Errorf("just before expiry: %v", err)
	}
	s.Now = func() time.Time { return t0.Add(15 * time.Minute) }
	if _, err := s.Verify(tok, "r1", lfs.Upload); !errors.Is(err, ErrInvalid) {
		t.Errorf("at expiry: %v", err)
	}
}

func TestSignerCopiesKey(t *testing.T) {
	k := secret(1)
	s, err := NewSigner([]Key{{ID: "k", Secret: k}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, _ := s.Mint("a", "r", lfs.Download)
	k[0] = 99
	if _, err := s.Verify(tok, "r", lfs.Download); err != nil {
		t.Errorf("caller mutation of key affected signer: %v", err)
	}
}

func FuzzVerify(f *testing.F) {
	s, err := NewSigner([]Key{key}, time.Minute)
	if err != nil {
		f.Fatal(err)
	}
	good, _, _ := s.Mint("alice", "r1", lfs.Download)
	f.Add(good)
	f.Add("")
	f.Add("v1.k1.a.b")
	f.Fuzz(func(t *testing.T, tok string) {
		c, err := s.Verify(tok, "other-repo", lfs.Upload)
		if err == nil {
			t.Fatalf("forged token accepted: %q -> %+v", tok, c)
		}
	})
}

// A correctly signed token whose payload is not valid base64 or JSON must
// still be rejected: the MAC proves origin, not well-formedness.
func TestVerifyRejectsSignedGarbage(t *testing.T) {
	s := newSigner(t)
	for name, p := range map[string]string{
		"not base64": "!!!!",
		"not json":   enc.EncodeToString([]byte("not json")),
		"no id":      enc.EncodeToString([]byte(`{"sub":"alice","rid":"r1","op":"download","exp":9999999999}`)),
	} {
		tok := "v1.k1." + p + "." + enc.EncodeToString(mac(key, p))
		if _, err := s.Verify(tok, "r1", lfs.Download); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}
