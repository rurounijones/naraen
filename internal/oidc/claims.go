// Package oidc checks CI workload identity claims against the workload-trust
// entries in the datastore. The caller verifies the token's signature against
// the matching trust entry's JWKS first; Check then enforces everything else on
// the signed payload. Check reads the repo claim itself, because which claim
// names the repo depends on the trust entry that matches.
package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/rurounijones/naraen/internal/datastore"
)

// maxPayload bounds the decoded JWT payload before parsing.
const maxPayload = 8 << 10

// ErrRejected is returned for every failed check, without detail.
var ErrRejected = errors.New("oidc: token rejected")

// Check parses payload (a signature-verified JWT claims set) and matches it
// against trusts. It returns the repo ID the workload may act on and its
// maximum level, which is never above read. The token must name exactly one
// audience, equal to the trust entry's custom audience; it must not be
// expired or not yet valid.
func Check(payload []byte, trusts []datastore.WorkloadTrust, now time.Time) (repoID string, max datastore.Level, err error) {
	if len(payload) > maxPayload {
		return "", datastore.LevelNone, ErrRejected
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", datastore.LevelNone, ErrRejected
	}
	var iss string
	var exp int64
	if !str(claims["iss"], &iss) || !num(claims["exp"], &exp) || !now.Before(time.Unix(exp, 0)) {
		return "", datastore.LevelNone, ErrRejected
	}
	if raw, ok := claims["nbf"]; ok {
		var nbf int64
		if !num(raw, &nbf) || now.Before(time.Unix(nbf, 0)) {
			return "", datastore.LevelNone, ErrRejected
		}
	}
	aud, ok := audience(claims["aud"])
	if !ok {
		return "", datastore.LevelNone, ErrRejected
	}
	for _, t := range trusts {
		if t.Issuer == "" || t.Audience == "" || t.Issuer != iss || t.Audience != aud {
			continue
		}
		var repo string
		if !str(claims[t.RepoClaim], &repo) || repo == "" {
			return "", datastore.LevelNone, ErrRejected
		}
		return repo, min(t.MaxLevel, datastore.LevelRead), nil
	}
	return "", datastore.LevelNone, ErrRejected
}

// audience returns the single audience of a JWT, which may be a string or a
// one-element array. More than one audience is refused: a token minted for
// several services is one that some other service could also replay.
func audience(raw json.RawMessage) (string, bool) {
	var one string
	if str(raw, &one) {
		return one, true
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil || len(many) != 1 {
		return "", false
	}
	return many[0], true
}

func str(raw json.RawMessage, v *string) bool {
	return bytes.HasPrefix(raw, []byte(`"`)) && json.Unmarshal(raw, v) == nil
}

func num(raw json.RawMessage, v *int64) bool {
	return raw != nil && json.Unmarshal(raw, v) == nil
}
