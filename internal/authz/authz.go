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

// Reason says why a request was denied. It is for audit records and metrics
// only and must never reach the client.
type Reason string

// Denial reasons. They are metric label values, so the set is closed.
const (
	ReasonNotReady          Reason = "not_ready"
	ReasonStale             Reason = "stale"
	ReasonUnknownKey        Reason = "unknown_key"
	ReasonBadPath           Reason = "bad_path"
	ReasonUnknownRepo       Reason = "unknown_repo"
	ReasonUnknownIdentity   Reason = "unknown_identity"
	ReasonInactiveIdentity  Reason = "inactive_identity"
	ReasonInsufficientGrant Reason = "insufficient_grant"
	ReasonBadOperation      Reason = "bad_operation"
)

// deniedError is ErrDenied with the reason attached for the server's own
// records. Its message is ErrDenied's, so printing it reveals nothing.
type deniedError struct{ reason Reason }

func (e *deniedError) Error() string { return ErrDenied.Error() }

func (e *deniedError) Is(target error) bool { return target == ErrDenied }

func deny(r Reason) error { return &deniedError{reason: r} }

// ReasonOf returns why err denied a request, or "" if err is not a denial.
func ReasonOf(err error) Reason {
	var d *deniedError
	if errors.As(err, &d) {
		return d.reason
	}
	return ""
}

// Authorizer decides against whatever snapshot the store currently holds.
type Authorizer struct {
	store *datastore.Store
}

// New returns an Authorizer reading from store.
func New(store *datastore.Store) *Authorizer { return &Authorizer{store: store} }

// current returns the live snapshot, or the denial that its absence means.
func (a *Authorizer) current() (*datastore.Snapshot, error) {
	snap, err := a.store.Current()
	if errors.Is(err, datastore.ErrStale) {
		return nil, deny(ReasonStale)
	}
	if err != nil {
		return nil, deny(ReasonNotReady)
	}
	return snap, nil
}

// IdentityForKey resolves an SSH key fingerprint to an active identity.
func (a *Authorizer) IdentityForKey(fingerprint string) (datastore.Identity, error) {
	snap, err := a.current()
	if err != nil {
		return datastore.Identity{}, err
	}
	id, ok := snap.KeyOwner(fingerprint)
	if ok {
		return id, nil
	}
	// A removed member still offering their key is worth telling apart
	// from a stranger in the audit record.
	if holder, ok := snap.KeyHolder(fingerprint); ok && snap.Deactivated(holder) {
		return datastore.Identity{}, deny(ReasonInactiveIdentity)
	}
	return datastore.Identity{}, deny(ReasonUnknownKey)
}

// Authorize checks that identityID may perform op on the repo at rawPath and
// returns the resolved repo ID.
func (a *Authorizer) Authorize(identityID, rawPath string, op lfs.Operation) (repoID string, err error) {
	snap, err := a.current()
	if err != nil {
		return "", err
	}
	path, err := pathnorm.Normalize(rawPath)
	if err != nil {
		return "", deny(ReasonBadPath)
	}
	repo, ok := snap.RepoByPath(path)
	if !ok {
		return "", deny(ReasonUnknownRepo)
	}
	if err := permitted(snap, identityID, repo.ID, op); err != nil {
		return "", err
	}
	return repo.ID, nil
}

// Recheck confirms that a decision made earlier, such as the one behind a
// bearer token, still holds in the current snapshot. The Batch API calls it on
// every request, so access removed by a sync or a webhook stops new links at
// once instead of when the token expires.
func (a *Authorizer) Recheck(identityID, repoID string, op lfs.Operation) error {
	snap, err := a.current()
	if err != nil {
		return err
	}
	// A grant can only reference a repo in the same snapshot, so a repo that
	// has gone away has no grants left to find.
	return permitted(snap, identityID, repoID, op)
}

func permitted(snap *datastore.Snapshot, identityID, repoID string, op lfs.Operation) error {
	if _, ok := snap.Identity(identityID); !ok {
		if snap.Deactivated(identityID) {
			return deny(ReasonInactiveIdentity)
		}
		return deny(ReasonUnknownIdentity)
	}
	need, ok := required(op)
	if !ok {
		return deny(ReasonBadOperation)
	}
	if snap.GrantLevel(identityID, repoID) < need {
		return deny(ReasonInsufficientGrant)
	}
	return nil
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
