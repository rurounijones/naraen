// Package pathnorm turns a client-supplied repository path into the canonical
// "owner/repo" form used to resolve a repo ID. It is deliberately strict: anything
// ambiguous is rejected rather than cleaned up.
package pathnorm

import (
	"errors"
	"strings"
)

// MaxLength bounds the raw input before any processing.
const MaxLength = 200

// ErrInvalid is returned for every rejected path. Callers must not reveal why.
var ErrInvalid = errors.New("pathnorm: invalid repository path")

// Normalize returns the lowercase "owner/repo" form of raw. A single leading
// slash and a trailing ".git" are tolerated; everything else unusual (dot
// segments, encoded or backslash separators, empty segments, extra segments,
// control characters, non-ASCII) is rejected.
func Normalize(raw string) (string, error) {
	if raw == "" || len(raw) > MaxLength {
		return "", ErrInvalid
	}
	p := strings.ToLower(strings.TrimPrefix(raw, "/"))
	p = strings.TrimSuffix(p, ".git")

	parts := strings.Split(p, "/")
	if len(parts) != 2 {
		return "", ErrInvalid
	}
	for _, seg := range parts {
		if !validSegment(seg) {
			return "", ErrInvalid
		}
	}
	return p, nil
}

// validSegment expects an already lower-cased segment.
func validSegment(s string) bool {
	if s == "" || s == "." || s == ".." || strings.HasSuffix(s, ".git") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !validByte(s[i]) {
			return false
		}
	}
	return true
}

func validByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}
