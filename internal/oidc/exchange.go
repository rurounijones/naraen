package oidc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/pathnorm"
	"github.com/rurounijones/naraen/internal/telemetry"
	"github.com/rurounijones/naraen/internal/token"
)

// WorkloadPrefix starts the identity ID of every CI workload. A provider that
// registers a workload trust for a repo also writes the identity
// WorkloadPrefix+repoID, of kind workload, with a read grant on that repo, so
// a workload is checked against a grant like any other identity.
const WorkloadPrefix = "workload:"

// Refusal reasons the exchange adds to authz's. They are metric label values.
const (
	reasonBadOIDC      = "bad_oidc"
	reasonRepoMismatch = "repo_mismatch"
)

// Exchange swaps a CI workload's OIDC token for a read-only LFS token for the
// repo in the URL. It answers POST /{owner}/{repo}/ci/token with the same JSON
// git-lfs-authenticate prints, so a job can put the header straight into its
// git configuration.
type Exchange struct {
	Store  *datastore.Store
	Authz  *authz.Authorizer
	Tokens *token.Signer
	// Base is the public HTTPS origin the href starts with.
	Base string
	Rec  *telemetry.Recorder
	Log  *slog.Logger
	// Now is replaceable in tests.
	Now func() time.Time
}

type exchangeResponse struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header"`
	ExpiresIn int64             `json:"expires_in"`
}

// ServeHTTP verifies the OIDC token's signature against the keys of the
// trust entries for its issuer, checks its claims against the trust that
// signed it, and requires the repo it names to be the repo in the URL. Any
// failure up to there is 401: the caller has not proven anything. After it,
// a refusal is 403.
func (x *Exchange) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := x.Log.With("remote", r.RemoteAddr)
	snap, err := x.Store.Current()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	raw, ok := token.Bearer(r.Header.Get("Authorization"))
	if !ok {
		x.refuse(ctx, w, log, http.StatusUnauthorized, reasonBadOIDC)
		return
	}
	repoID, issuer, ok := x.verify(snap, raw)
	if !ok {
		x.refuse(ctx, w, log, http.StatusUnauthorized, reasonBadOIDC)
		return
	}
	subject := WorkloadPrefix + repoID
	log = log.With("identity", subject, "identity_type", string(datastore.KindWorkload), "issuer", issuer)
	rawPath := r.PathValue("owner") + "/" + r.PathValue("repo")
	urlRepo, err := x.Authz.Authorize(subject, rawPath, lfs.Download)
	if err != nil {
		x.refuse(ctx, w, log, http.StatusForbidden, string(authz.ReasonOf(err)))
		return
	}
	if urlRepo != repoID {
		x.refuse(ctx, w, log, http.StatusForbidden, reasonRepoMismatch)
		return
	}
	tok, claims, err := x.Tokens.Mint(subject, repoID, lfs.Download)
	if err != nil {
		log.ErrorContext(ctx, "token exchange failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Authorize accepted the path, so it normalizes.
	path, _ := pathnorm.Normalize(rawPath)
	log.InfoContext(ctx, "token issued", "token_id", claims.ID, "repo", path, "repo_id", repoID,
		"operation", string(lfs.Download), "expires", time.Unix(claims.Expires, 0).UTC())
	x.Rec.TokenIssued(ctx, string(lfs.Download), repoID, subject)
	writeJSON(w, http.StatusOK, exchangeResponse{
		Href:      x.Base + "/" + path,
		Header:    map[string]string{"Authorization": "Bearer " + tok},
		ExpiresIn: int64(x.Tokens.TTL().Seconds()),
	})
}

// verify finds the trust entry whose keys signed raw and whose claims rules
// it meets, and returns the repo ID it names. The signature and the claims
// are checked against the same entry, so one issuer's keys can never vouch
// for claims meant for another entry's audience.
func (x *Exchange) verify(snap *datastore.Snapshot, raw string) (repoID, issuer string, ok bool) {
	iss := unverifiedIssuer(raw)
	for _, t := range snap.Trusts() {
		if iss == "" || t.Issuer != iss {
			continue
		}
		payload, err := VerifySignature(raw, t.JWKS)
		if err != nil {
			continue
		}
		repoID, _, err := Check(payload, []datastore.WorkloadTrust{t}, x.Now())
		if err != nil {
			continue
		}
		return repoID, iss, true
	}
	return "", "", false
}

func (x *Exchange) refuse(ctx context.Context, w http.ResponseWriter, log *slog.Logger, status int, reason string) {
	log.InfoContext(ctx, "token exchange refused", "status", status, "reason", reason)
	x.Rec.AuthFailure(ctx, reason, string(datastore.KindWorkload))
	msg := "unauthorized"
	if status == http.StatusForbidden {
		msg = "forbidden"
	}
	writeError(w, status, msg)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, struct {
		Message string `json:"message"`
	}{msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The bodies hold only strings and numbers, so encoding cannot fail; a
	// failed write means the client has gone.
	_ = json.NewEncoder(w).Encode(v)
}
