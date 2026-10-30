package sshd

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/rurounijones/naraen/internal/authz"
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
	log    *slog.Logger
}

// NewAuthenticator returns an Authenticator whose hrefs start with base, the
// public HTTPS origin.
func NewAuthenticator(a *authz.Authorizer, tokens *token.Signer, base string, log *slog.Logger) *Authenticator {
	return &Authenticator{authz: a, tokens: tokens, base: base, log: log}
}

// authResponse is what git-lfs expects from git-lfs-authenticate.
type authResponse struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header"`
	ExpiresIn int64             `json:"expires_in"`
}

// Handle implements Handler. It returns ErrUnsupported, a denial from authz
// (which says nothing about why), or an error minting the token.
func (a *Authenticator) Handle(ctx context.Context, identityID string, cmd Command) ([]byte, error) {
	if cmd.Name != CmdAuthenticate {
		return nil, ErrUnsupported
	}
	repoID, err := a.authz.Authorize(identityID, cmd.Repo, cmd.Op)
	if err != nil {
		return nil, err
	}
	tok, claims, err := a.tokens.Mint(identityID, repoID, cmd.Op)
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
	// An audit record of the decision. The token ID is not a credential;
	// the token itself and the href are never logged.
	a.log.InfoContext(ctx, "token issued", "identity", identityID, "token_id", claims.ID, "repo_id", repoID, "operation", cmd.Op)
	return append(out, '\n'), nil
}
