// Package oid validates Git LFS object IDs before they reach an S3 key.
package oid

import "errors"

// Length is the number of characters in a SHA-256 hex digest.
const Length = 64

// ErrInvalid is returned for anything other than 64 lowercase hex characters.
var ErrInvalid = errors.New("oid: must be 64 lowercase hex characters")

// OID is a validated object ID.
type OID string

// Valid reports whether s is exactly 64 lowercase hex characters.
func Valid(s string) bool {
	if len(s) != Length {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Parse validates s and returns it as an OID.
func Parse(s string) (OID, error) {
	if !Valid(s) {
		return "", ErrInvalid
	}
	return OID(s), nil
}
