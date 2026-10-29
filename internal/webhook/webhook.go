// Package webhook verifies GitHub webhook signatures.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// ErrBadSignature is returned for any missing, malformed or mismatching signature.
var ErrBadSignature = errors.New("webhook: bad signature")

const prefix = "sha256="

// Verify checks header (the X-Hub-Signature-256 value) against body using secret.
// An empty secret never verifies, so a missing configuration cannot accept input.
func Verify(secret, body []byte, header string) error {
	if len(secret) == 0 || !strings.HasPrefix(header, prefix) {
		return ErrBadSignature
	}
	got, err := hex.DecodeString(header[len(prefix):])
	if err != nil {
		return ErrBadSignature
	}
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	if !hmac.Equal(got, m.Sum(nil)) {
		return ErrBadSignature
	}
	return nil
}
