package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
)

const (
	// maxToken bounds a compact JWT before any decoding.
	maxToken = 16 << 10
	// minRSABits is the smallest RSA modulus accepted for RS256.
	minRSABits = 2048
	// p256Coord is the size of a P-256 coordinate and of each half of an
	// ES256 signature.
	p256Coord = 32
)

var b64 = base64.RawURLEncoding.Strict()

type jwsHeader struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Crit json.RawMessage `json:"crit"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// VerifySignature checks a compact JWS against the keys of a JWKS document
// and returns the signed payload. Only RS256 (RSA of at least 2048 bits) and
// ES256 (P-256) are accepted, which rules out "none" and the HMAC algorithms
// whose shared secret an attacker could take from the public key. The key is
// chosen by the header's kid, which is required, and must be of the kind the
// algorithm needs; a key that states its own algorithm or use must agree. A
// header with critical extensions is refused, since none are understood.
func VerifySignature(tok, jwks string) ([]byte, error) {
	if len(tok) > maxToken {
		return nil, ErrRejected
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, ErrRejected
	}
	rawHeader, err1 := b64.DecodeString(parts[0])
	payload, err2 := b64.DecodeString(parts[1])
	sig, err3 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, ErrRejected
	}
	var h jwsHeader
	if json.Unmarshal(rawHeader, &h) != nil || h.Kid == "" || h.Crit != nil {
		return nil, ErrRejected
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if json.Unmarshal([]byte(jwks), &set) != nil {
		return nil, ErrRejected
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	for _, k := range set.Keys {
		if k.Kid != h.Kid || (k.Alg != "" && k.Alg != h.Alg) || (k.Use != "" && k.Use != "sig") {
			continue
		}
		if verify(h.Alg, k, digest[:], sig) {
			return payload, nil
		}
		return nil, ErrRejected
	}
	return nil, ErrRejected
}

// verify checks sig over digest with key k under alg.
func verify(alg string, k jwk, digest, sig []byte) bool {
	switch {
	case alg == "RS256" && k.Kty == "RSA":
		pub, ok := rsaKey(k)
		return ok && rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig) == nil
	case alg == "ES256" && k.Kty == "EC" && k.Crv == "P-256":
		pub, ok := p256Key(k)
		if !ok || len(sig) != 2*p256Coord {
			return false
		}
		r := new(big.Int).SetBytes(sig[:p256Coord])
		s := new(big.Int).SetBytes(sig[p256Coord:])
		return ecdsa.Verify(pub, digest, r, s)
	default:
		return false
	}
}

func rsaKey(k jwk) (*rsa.PublicKey, bool) {
	n, err1 := b64.DecodeString(k.N)
	e, err2 := b64.DecodeString(k.E)
	// A public exponent wider than 4 bytes is not one any issuer uses, and
	// would not fit rsa.PublicKey's int on every platform.
	if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
		return nil, false
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if pub.N.BitLen() < minRSABits || pub.E < 3 || pub.E%2 == 0 {
		return nil, false
	}
	return pub, true
}

func p256Key(k jwk) (*ecdsa.PublicKey, bool) {
	x, err1 := b64.DecodeString(k.X)
	y, err2 := b64.DecodeString(k.Y)
	if err1 != nil || err2 != nil || len(x) != p256Coord || len(y) != p256Coord {
		return nil, false
	}
	// ParseUncompressedPublicKey rejects points that are not on the curve.
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	return pub, err == nil
}

// unverifiedIssuer reads iss from a JWT without checking anything, only to
// choose which trust entries' keys to verify it with. Nothing else is taken
// from the token until its signature verifies.
func unverifiedIssuer(tok string) string {
	parts := strings.Split(tok, ".")
	if len(tok) > maxToken || len(parts) != 3 {
		return ""
	}
	raw, err := b64.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return ""
	}
	return c.Iss
}
