// Package authz makes request-path access decisions from the current datastore
// snapshot. It makes no network calls and knows nothing about any provider.
// Every failure mode is a denial.
package authz

import (
	"errors"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/pathnorm"
)

// ErrDenied is the only error callers should surface. It deliberately carries no
// reason, so responses cannot be used to probe which repos or keys exist.
var ErrDenied = errors.New("authz: denied")

// Authorizer decides against whatever snapshot the store currently holds.
type Authorizer struct {
	store *datastore.Store
}

// New returns an Authorizer reading from store.
func New(store *datastore.Store) *Authorizer { return &Authorizer{store: store} }

// IdentityForKey resolves an SSH key fingerprint to an active identity.
func (a *Authorizer) IdentityForKey(fingerprint string) (datastore.Identity, error) {
	snap, err := a.store.Current()
	if err != nil {
		return datastore.Identity{}, ErrDenied
	}
	id, ok := snap.KeyOwner(fingerprint)
	if !ok {
		return datastore.Identity{}, ErrDenied
	}
	return id, nil
}

// Authorize checks that identityID may perform op on the repo at rawPath and
// returns the resolved repo ID.
func (a *Authorizer) Authorize(identityID, rawPath string, op lfs.Operation) (repoID string, err error) {
	snap, err := a.store.Current()
	if err != nil {
		return "", ErrDenied
	}
	path, err := pathnorm.Normalize(rawPath)
	if err != nil {
		return "", ErrDenied
	}
	repo, ok := snap.RepoByPath(path)
	if !ok || !permitted(snap, identityID, repo.ID, op) {
		return "", ErrDenied
	}
	return repo.ID, nil
}

// Recheck confirms that a decision made earlier, such as the one behind a
// bearer token, still holds in the current snapshot. The Batch API calls it on
// every request, so access removed by a sync or a webhook stops new links at
// once instead of when the token expires.
func (a *Authorizer) Recheck(identityID, repoID string, op lfs.Operation) error {
	snap, err := a.store.Current()
	if err != nil {
		return ErrDenied
	}
	// A grant can only reference a repo in the same snapshot, so a repo that
	// has gone away has no grants left to find.
	if !permitted(snap, identityID, repoID, op) {
		return ErrDenied
	}
	return nil
}

func permitted(snap *datastore.Snapshot, identityID, repoID string, op lfs.Operation) bool {
	if _, ok := snap.Identity(identityID); !ok {
		return false
	}
	need, ok := required(op)
	return ok && snap.GrantLevel(identityID, repoID) >= need
}

// required maps an operation to the minimum level it needs. Unknown operations
// have no mapping and are denied.
func required(op lfs.Operation) (datastore.Level, bool) {
	switch op {
	case lfs.Download:
		return datastore.LevelRead, true
	case lfs.Upload:
		return datastore.LevelWrite, true
	default:
		return datastore.LevelNone, false
	}
}
