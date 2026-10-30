package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// signer makes test JWTs and the JWKS entry that verifies them.
type signer struct {
	alg string
	kid string
	ec  *ecdsa.PrivateKey
	rsa *rsa.PrivateKey
	// point is the EC public key, uncompressed: 0x04, then x and y.
	point []byte
}

func newES256(t testing.TB, kid string) *signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return &signer{alg: "ES256", kid: kid, ec: k, point: point}
}

func newRS256(t testing.TB, kid string, bits int) *signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{alg: "RS256", kid: kid, rsa: k}
}

func pad32(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }

// jwk returns the public key as a JWKS entry.
func (s *signer) jwk() map[string]string {
	if s.ec != nil {
		x, y := s.point[1:33], s.point[33:]
		return map[string]string{"kty": "EC", "crv": "P-256", "kid": s.kid, "x": b64.EncodeToString(x), "y": b64.EncodeToString(y)}
	}
	return map[string]string{
		"kty": "RSA", "kid": s.kid,
		"n": b64.EncodeToString(s.rsa.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(s.rsa.E)).Bytes()),
	}
}

func jwks(keys ...map[string]string) string {
	out, _ := json.Marshal(map[string]any{"keys": keys})
	return string(out)
}

// sign returns a compact JWT over claims with the given header fields.
func (s *signer) sign(t testing.TB, header map[string]any, claims map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": s.alg, "kid": s.kid, "typ": "JWT"}
	for k, v := range header {
		h[k] = v
	}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	input := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	digest := sha256.Sum256([]byte(input))
	var sig []byte
	if s.ec != nil {
		r, ss, err := ecdsa.Sign(rand.Reader, s.ec, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = append(pad32(r.Bytes()), pad32(ss.Bytes())...)
	} else {
		var err error
		if sig, err = rsa.SignPKCS1v15(rand.Reader, s.rsa, crypto.SHA256, digest[:]); err != nil {
			t.Fatal(err)
		}
	}
	return input + "." + b64.EncodeToString(sig)
}

var someClaims = map[string]any{"iss": "https://issuer.test", "repository_id": "r1"}

func TestVerifySignatureAccepts(t *testing.T) {
	for _, s := range []*signer{newES256(t, "ec1"), newRS256(t, "rsa1", 2048)} {
		tok := s.sign(t, nil, someClaims)
		payload, err := VerifySignature(tok, jwks(s.jwk()))
		if err != nil || !strings.Contains(string(payload), `"repository_id":"r1"`) {
			t.Errorf("%s: %s, %v", s.alg, payload, err)
		}
		// A key that names its algorithm and use, correctly, is fine too.
		k := s.jwk()
		k["alg"], k["use"] = s.alg, "sig"
		if _, err := VerifySignature(tok, jwks(map[string]string{"kid": "other", "kty": "EC"}, k)); err != nil {
			t.Errorf("%s with alg and use: %v", s.alg, err)
		}
	}
}

func TestVerifySignatureRejects(t *testing.T) {
	ec := newES256(t, "ec1")
	rs := newRS256(t, "rsa1", 2048)
	good := ec.sign(t, nil, someClaims)
	parts := strings.Split(good, ".")
	other := newES256(t, "ec1")
	small := newRS256(t, "rsa1", 1024)

	withKey := func(base map[string]string, k, v string) string {
		m := map[string]string{}
		for kk, vv := range base {
			m[kk] = vv
		}
		m[k] = v
		return jwks(m)
	}
	ecKeys, rsaKeys := jwks(ec.jwk()), jwks(rs.jwk())
	for name, tt := range map[string]struct{ tok, keys string }{
		"too long":          {strings.Repeat("a", maxToken+1), ecKeys},
		"two parts":         {parts[0] + "." + parts[1], ecKeys},
		"bad header b64":    {"!" + good[1:], ecKeys},
		"bad payload b64":   {parts[0] + ".!." + parts[2], ecKeys},
		"bad signature b64": {parts[0] + "." + parts[1] + ".!", ecKeys},
		"header not json":   {b64.EncodeToString([]byte("x")) + "." + parts[1] + "." + parts[2], ecKeys},
		"no kid":            {ec.sign(t, map[string]any{"kid": ""}, someClaims), ecKeys},
		"critical ext":      {ec.sign(t, map[string]any{"crit": []string{"exp"}}, someClaims), ecKeys},
		"jwks not json":     {good, "nope"},
		"unknown kid":       {ec.sign(t, map[string]any{"kid": "ec2"}, someClaims), ecKeys},
		"key alg differs":   {good, withKey(ec.jwk(), "alg", "RS256")},
		"key for enc":       {good, withKey(ec.jwk(), "use", "enc")},
		"alg none":          {ec.sign(t, map[string]any{"alg": "none"}, someClaims), ecKeys},
		"alg HS256":         {ec.sign(t, map[string]any{"alg": "HS256"}, someClaims), ecKeys},
		"ES256 by RSA key":  {ec.sign(t, map[string]any{"kid": "rsa1"}, someClaims), rsaKeys},
		"RS256 by EC key":   {rs.sign(t, map[string]any{"kid": "ec1"}, someClaims), ecKeys},
		"wrong curve":       {good, withKey(ec.jwk(), "crv", "P-384")},
		"other key":         {good, jwks(other.jwk())},
		"edited payload":    {parts[0] + "." + b64.EncodeToString([]byte(`{"iss":"x"}`)) + "." + parts[2], ecKeys},
		"short ES256 sig":   {parts[0] + "." + parts[1] + "." + b64.EncodeToString([]byte("short")), ecKeys},
		"x wrong length":    {good, withKey(ec.jwk(), "x", b64.EncodeToString([]byte("short")))},
		"x bad b64":         {good, withKey(ec.jwk(), "x", "!")},
		"y bad b64":         {good, withKey(ec.jwk(), "y", "!")},
		"point off curve":   {good, withKey(ec.jwk(), "y", b64.EncodeToString(make([]byte, 32)))},
		"RSA 1024 bits":     {small.sign(t, nil, someClaims), jwks(small.jwk())},
		"RSA even exponent": {rs.sign(t, nil, someClaims), withKey(rs.jwk(), "e", b64.EncodeToString([]byte{4}))},
		"RSA exponent 1":    {rs.sign(t, nil, someClaims), withKey(rs.jwk(), "e", b64.EncodeToString([]byte{1}))},
		"RSA wide exponent": {rs.sign(t, nil, someClaims), withKey(rs.jwk(), "e", b64.EncodeToString([]byte{1, 0, 0, 0, 1}))},
		"RSA no exponent":   {rs.sign(t, nil, someClaims), withKey(rs.jwk(), "e", "")},
		"RSA n bad b64":     {rs.sign(t, nil, someClaims), withKey(rs.jwk(), "n", "!")},
		"RSA e bad b64":     {rs.sign(t, nil, someClaims), withKey(rs.jwk(), "e", "!")},
		"RSA bad signature": {rs.sign(t, nil, someClaims)[:len(rs.sign(t, nil, someClaims))-4] + "AAAA", rsaKeys},
	} {
		if p, err := VerifySignature(tt.tok, tt.keys); err == nil || p != nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestUnverifiedIssuer(t *testing.T) {
	s := newES256(t, "k")
	if got := unverifiedIssuer(s.sign(t, nil, someClaims)); got != "https://issuer.test" {
		t.Errorf("issuer = %q", got)
	}
	for name, tok := range map[string]string{
		"too long":    strings.Repeat("a.", maxToken),
		"one part":    "abc",
		"bad b64":     "a.!.c",
		"not json":    "a." + b64.EncodeToString([]byte("x")) + ".c",
		"no iss":      "a." + b64.EncodeToString([]byte(`{"sub":"x"}`)) + ".c",
		"iss not str": "a." + b64.EncodeToString([]byte(`{"iss":1}`)) + ".c",
	} {
		if got := unverifiedIssuer(tok); got != "" {
			t.Errorf("%s: issuer %q", name, got)
		}
	}
}

func FuzzVerifySignature(f *testing.F) {
	s := newES256(f, "ec1")
	keys := jwks(s.jwk())
	f.Add(s.sign(f, nil, someClaims))
	f.Add("a.b.c")
	f.Add("")
	f.Fuzz(func(t *testing.T, tok string) {
		payload, err := VerifySignature(tok, keys)
		if err == nil && payload == nil {
			t.Fatal("accepted with no payload")
		}
		_ = unverifiedIssuer(tok)
	})
}
