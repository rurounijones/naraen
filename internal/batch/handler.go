package batch

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/oid"
	"github.com/rurounijones/naraen/internal/pathnorm"
	"github.com/rurounijones/naraen/internal/storage"
	"github.com/rurounijones/naraen/internal/telemetry"
	"github.com/rurounijones/naraen/internal/token"
)

// ContentType is the Git LFS media type for Batch API bodies.
const ContentType = "application/vnd.git-lfs+json"

const (
	// statConcurrency bounds the S3 HEAD requests one batch makes at once.
	statConcurrency = 8
	// requestIDBytes is the size of a request ID: 128 random bits.
	requestIDBytes = 16
)

// reasonBadToken is the refusal reason the handler adds to authz's. Like those,
// it is a metric label value and never reaches the client.
const reasonBadToken = "bad_token"

// Handler serves POST /{owner}/{repo}/objects/batch.
type Handler struct {
	Store   *datastore.Store
	Authz   *authz.Authorizer
	Tokens  *token.Signer
	Objects storage.Presigner
	Rec     *telemetry.Recorder
	Log     *slog.Logger
	// Rand supplies request IDs.
	Rand io.Reader
}

type response struct {
	Transfer string           `json:"transfer"`
	Objects  []objectResponse `json:"objects"`
	HashAlgo string           `json:"hash_algo"`
}

type objectResponse struct {
	OID  oid.OID `json:"oid"`
	Size int64   `json:"size"`
	// Authenticated tells git-lfs the action URLs carry their own
	// authorization, so it never adds the bearer token or other
	// credentials to a request bound for S3.
	Authenticated bool              `json:"authenticated,omitempty"`
	Actions       map[string]action `json:"actions,omitempty"`
	Error         *objectError      `json:"error,omitempty"`
}

type action struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header,omitempty"`
	ExpiresAt time.Time         `json:"expires_at"`
}

type objectError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ServeHTTP authorizes the request and answers with one action per object.
//
// Everything up to and including the token check fails with 401 and the same
// message, so the response never tells an unauthenticated caller whether a
// repo exists. The token must have been minted for the repo the URL names,
// resolved to its ID: a token for one repo is useless at another's URL, and
// a rename or an alias removed since the token was issued fails closed. The
// grant is then rechecked against the current snapshot, so access revoked
// since the token was issued stops new links at once.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := h.Log.With("remote", r.RemoteAddr)
	tok, ok := Bearer(r.Header.Get("Authorization"))
	if !ok {
		h.refuse(ctx, w, log, http.StatusUnauthorized, reasonBadToken, telemetry.IdentityTypeUnknown)
		return
	}
	snap, err := h.Store.Current()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	repo, reason := resolve(snap, r.PathValue("owner")+"/"+r.PathValue("repo"))
	if reason != "" {
		h.refuse(ctx, w, log, http.StatusUnauthorized, reason, telemetry.IdentityTypeUnknown)
		return
	}
	req, err := ParseRequest(r.Body)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid request")
		return
	}
	claims, err := h.Tokens.Verify(tok, repo.ID, req.Operation)
	if err != nil {
		h.refuse(ctx, w, log, http.StatusUnauthorized, reasonBadToken, telemetry.IdentityTypeUnknown)
		return
	}
	kind := telemetry.IdentityTypeUnknown
	if id, ok := snap.Identity(claims.Subject); ok {
		kind = string(id.Kind)
	}
	log = log.With("identity", claims.Subject, "identity_type", kind, "token_id", claims.ID,
		"repo", repo.Path, "repo_id", repo.ID, "operation", string(req.Operation))
	if err := h.Authz.Recheck(claims.Subject, repo.ID, req.Operation); err != nil {
		h.refuse(ctx, w, log, http.StatusForbidden, string(authz.ReasonOf(err)), kind)
		return
	}
	raw := make([]byte, requestIDBytes)
	if _, err := io.ReadFull(h.Rand, raw); err != nil {
		log.ErrorContext(ctx, "batch failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	requestID := hex.EncodeToString(raw)
	objects, outcomes := h.actions(ctx, repo.ID, requestID, req)

	var links int
	var bytes int64
	for i, o := range outcomes {
		h.Rec.LinkOutcome(ctx, string(req.Operation), repo.ID, claims.Subject, o)
		if o == telemetry.OutcomeIssued {
			links++
			bytes += req.Objects[i].Size
			h.Rec.ObjectSize(ctx, string(req.Operation), repo.ID, req.Objects[i].Size)
		}
	}
	h.Rec.BytesRequested(ctx, string(req.Operation), repo.ID, claims.Subject, bytes)
	// The request ID is in every link's x-lfs-req, so S3's access log entries
	// lead back to this record, and through the token ID to the sign-in.
	log.InfoContext(ctx, "links issued", "request_id", requestID, "objects", len(req.Objects),
		"links", links, "bytes", bytes)
	writeJSON(w, http.StatusOK, response{Transfer: "basic", Objects: objects, HashAlgo: "sha256"})
}

// resolve maps the URL's repo path to a repo, or names why it cannot.
func resolve(snap *datastore.Snapshot, raw string) (datastore.Repo, string) {
	path, err := pathnorm.Normalize(raw)
	if err != nil {
		return datastore.Repo{}, string(authz.ReasonBadPath)
	}
	repo, ok := snap.RepoByPath(path)
	if !ok {
		return datastore.Repo{}, string(authz.ReasonUnknownRepo)
	}
	return repo, ""
}

// actions inspects the bucket and builds each object's answer, with at most
// statConcurrency requests to S3 in flight.
func (h *Handler) actions(ctx context.Context, repoID, requestID string, req Request) ([]objectResponse, []string) {
	objects := make([]objectResponse, len(req.Objects))
	outcomes := make([]string, len(req.Objects))
	sem := make(chan struct{}, statConcurrency)
	var wg sync.WaitGroup
	for i, o := range req.Objects {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			objects[i], outcomes[i] = h.object(ctx, repoID, requestID, req.Operation, o)
		}()
	}
	wg.Wait()
	return objects, outcomes
}

// object answers for one object. Uploads of stored objects get no action, so
// an existing object is never overwritten; downloads of objects that are not
// stored, or are stored at another size, get an error instead of a link.
func (h *Handler) object(ctx context.Context, repoID, requestID string, op lfs.Operation, o Object) (objectResponse, string) {
	resp := objectResponse{OID: o.OID, Size: o.Size}
	size, found, err := h.Objects.Stat(ctx, repoID, o.OID)
	if err != nil {
		h.Log.ErrorContext(ctx, "storage failed", "request_id", requestID, "oid", string(o.OID), "error", err)
		resp.Error = &objectError{Code: http.StatusInternalServerError, Message: "storage unavailable"}
		return resp, telemetry.OutcomeError
	}
	var link storage.Link
	switch {
	case op == lfs.Upload && found:
		return resp, telemetry.OutcomePresent
	case op == lfs.Download && !found:
		resp.Error = &objectError{Code: http.StatusNotFound, Message: "object not found"}
		return resp, telemetry.OutcomeMissing
	case op == lfs.Download && size != o.Size:
		resp.Error = &objectError{Code: http.StatusUnprocessableEntity, Message: "size does not match the stored object"}
		return resp, telemetry.OutcomeMismatch
	case op == lfs.Upload:
		link, err = h.Objects.PresignPut(ctx, repoID, o.OID, o.Size, requestID)
	default:
		link, err = h.Objects.PresignGet(ctx, repoID, o.OID, requestID)
	}
	if err != nil {
		h.Log.ErrorContext(ctx, "presign failed", "request_id", requestID, "oid", string(o.OID), "error", err)
		resp.Error = &objectError{Code: http.StatusInternalServerError, Message: "storage unavailable"}
		return resp, telemetry.OutcomeError
	}
	resp.Authenticated = true
	resp.Actions = map[string]action{string(op): {Href: link.URL, Header: link.Headers, ExpiresAt: link.Expires.UTC()}}
	return resp, telemetry.OutcomeIssued
}

// refuse logs and counts a refusal, and tells the client only the status.
func (h *Handler) refuse(ctx context.Context, w http.ResponseWriter, log *slog.Logger, status int, reason, kind string) {
	log.InfoContext(ctx, "batch refused", "status", status, "reason", reason)
	h.Rec.AuthFailure(ctx, reason, kind)
	msg := "unauthorized"
	if status == http.StatusForbidden {
		msg = "forbidden"
	}
	writeError(w, status, msg)
}

// Bearer extracts the token from an Authorization header value.
func Bearer(header string) (string, bool) {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || tok == "" || strings.ContainsAny(tok, " \t") {
		return "", false
	}
	return tok, true
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, struct {
		Message string `json:"message"`
	}{msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(status)
	// The bodies hold only strings, numbers and times, so encoding cannot
	// fail; a failed write means the client has gone.
	_ = json.NewEncoder(w).Encode(v)
}

// Unconfigured answers every Batch request with 503. A development server
// without a bucket mounts it, so SSH authentication can still be tried
// without storage.
func Unconfigured() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusServiceUnavailable, "storage not configured")
	})
}
