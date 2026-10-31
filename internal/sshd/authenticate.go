package sshd

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/telemetry"
	"github.com/rurounijones/naraen/internal/token"
)

// ErrUnsupported is returned for git-lfs-transfer. Unlike every other refusal
// it is reported to the client as such, because it says nothing about access:
// git-lfs tries git-lfs-transfer first and falls back to git-lfs-authenticate
// when it fails, and naraen never carries file bytes itself.
var ErrUnsupported = errors.New("git-lfs-transfer is not supported")

// Authenticator answers git-lfs-authenticate with the Batch API address and a
// bearer token bound to the identity, the repo ID and the operation.
type Authenticator struct {
	authz  *authz.Authorizer
	tokens *token.Signer
	base   string
	rec    *telemetry.Recorder
}

// NewAuthenticator returns an Authenticator whose hrefs start with base, the
// public HTTPS origin.
func NewAuthenticator(a *authz.Authorizer, tokens *token.Signer, base string, rec *telemetry.Recorder) *Authenticator {
	return &Authenticator{authz: a, tokens: tokens, base: base, rec: rec}
}

// authResponse is what git-lfs expects from git-lfs-authenticate.
type authResponse struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header"`
	ExpiresIn int64             `json:"expires_in"`
}

// Handle implements Handler. It returns ErrUnsupported, a denial from authz
// (which says nothing about why), or an error minting the token.
func (a *Authenticator) Handle(ctx context.Context, s Session, cmd Command) ([]byte, error) {
	if cmd.Name != CmdAuthenticate {
		return nil, ErrUnsupported
	}
	repoID, err := a.authz.Authorize(s.IdentityID, cmd.Repo, cmd.Op)
	if err != nil {
		return nil, err
	}
	tok, claims, err := a.tokens.Mint(s.IdentityID, repoID, cmd.Op)
	if err != nil {
		return nil, err
	}
	// The response holds only strings and an integer, so Marshal cannot fail.
	out, _ := json.Marshal(authResponse{
		// The client's own spelling of the path, already normalized: an alias
		// resolves to the same repo ID when the Batch API is called.
		Href:      a.base + "/" + cmd.Repo,
		Header:    map[string]string{"Authorization": "Bearer " + tok},
		ExpiresIn: int64(a.tokens.TTL().Seconds()),
	})
	// The audit record of the decision. The token ID is not a credential;
	// the token itself and the href are never logged.
	s.Log.InfoContext(ctx, "token issued", "token_id", claims.ID, "repo", cmd.Repo, "repo_id", repoID,
		"operation", string(cmd.Op), "expires", time.Unix(claims.Expires, 0).UTC())
	telemetry.Annotate(ctx, attribute.String(telemetry.AttrTokenID, claims.ID), attribute.String(telemetry.AttrRepoID, repoID))
	a.rec.TokenIssued(ctx, string(cmd.Op), repoID, s.IdentityID)
	return append(out, '\n'), nil
}
