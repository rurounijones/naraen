// Package datastore holds the neutral, immutable view of identities, keys, repos
// and grants that the request path decides against. Providers write it; the
// request path only reads it.
package datastore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rurounijones/naraen/internal/pathnorm"
)

// Level is a repo permission level, ordered from least to most privileged.
// It is stored by name, never by number, so adding a level cannot silently
// renumber grants that were already written down.
type Level int

const (
	LevelNone Level = iota
	LevelRead
	LevelWrite
	LevelMaintain
	LevelAdmin
)

var levelNames = [...]string{"none", "read", "write", "maintain", "admin"}

// String returns the level's name.
func (l Level) String() string {
	if l < LevelNone || l > LevelAdmin {
		return fmt.Sprintf("Level(%d)", int(l))
	}
	return levelNames[l]
}

// MarshalText encodes a level by name and refuses levels that do not exist.
func (l Level) MarshalText() ([]byte, error) {
	if l < LevelNone || l > LevelAdmin {
		return nil, fmt.Errorf("datastore: invalid level %d", int(l))
	}
	return []byte(levelNames[l]), nil
}

// UnmarshalText decodes a level name. Numbers and unknown names are refused.
func (l *Level) UnmarshalText(b []byte) error {
	for i, name := range levelNames {
		if string(b) == name {
			*l = Level(i)
			return nil
		}
	}
	return fmt.Errorf("datastore: unknown level %q", b)
}

// IdentityKind says what an identity represents.
type IdentityKind string

const (
	KindPerson    IdentityKind = "person"
	KindDeployKey IdentityKind = "deploy_key"
	KindWorkload  IdentityKind = "workload"
)

// Identity is a person, a repo deploy key or a CI workload.
type Identity struct {
	ID     string       `json:"id"`
	Kind   IdentityKind `json:"kind"`
	Name   string       `json:"name"`
	Active bool         `json:"active"`
}

// Key maps an SSH key fingerprint ("SHA256:...") to its one owning identity.
type Key struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	IdentityID  string `json:"identity_id"`
}

// repoIDPattern is what a repo ID may hold. The ID names the repo's folder in
// the bucket, so a slash in one could reach into another repo's folder.
var repoIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Repo is a repository with a stable ID, a canonical path and rename aliases.
type Repo struct {
	ID      string   `json:"id"`
	Path    string   `json:"path"`
	Aliases []string `json:"aliases,omitempty"`
}

// Grant gives an identity a level on a repo.
type Grant struct {
	IdentityID string `json:"identity_id"`
	RepoID     string `json:"repo_id"`
	Level      Level  `json:"level"`
}

// WorkloadTrust describes how to verify CI OIDC tokens for a repo claim. The
// provider fetches the issuer's signing keys into JWKS, so verifying a CI token
// needs no network call on the request path.
type WorkloadTrust struct {
	Issuer    string `json:"issuer"`
	Audience  string `json:"audience"`
	JWKS      string `json:"jwks"`
	RepoClaim string `json:"repo_claim"`
	// MaxLevel must be LevelRead: CI workloads are read-only by design, and
	// the entry records the cap so that nothing has to assume it.
	MaxLevel Level `json:"max_level"`
}

// Meta describes where and when a provider says a snapshot was built. It is
// informational: freshness is measured by the Store from its own clock.
type Meta struct {
	Provider string    `json:"provider"`
	Version  string    `json:"version"`
	SyncedAt time.Time `json:"synced_at"`
}

// Data is the raw content a provider hands to NewSnapshot.
type Data struct {
	Meta       Meta            `json:"meta"`
	Identities []Identity      `json:"identities"`
	Keys       []Key           `json:"keys"`
	Repos      []Repo          `json:"repos"`
	Grants     []Grant         `json:"grants"`
	Trusts     []WorkloadTrust `json:"trusts"`
}

type grantKey struct{ identityID, repoID string }

// Snapshot is an immutable, indexed copy of Data. All lookups fail closed:
// anything absent returns the zero value and false.
type Snapshot struct {
	meta       Meta
	identities map[string]Identity
	keys       map[string]Key
	repos      map[string]Repo
	repoByPath map[string]string
	grants     map[grantKey]Level
	trusts     []WorkloadTrust
}

// NewSnapshot indexes d. It rejects data that is ambiguous or malformed,
// because ambiguity in an access datastore must never be resolved silently.
func NewSnapshot(d Data) (*Snapshot, error) {
	s := &Snapshot{
		meta:       d.Meta,
		identities: make(map[string]Identity, len(d.Identities)),
		keys:       make(map[string]Key, len(d.Keys)),
		repos:      make(map[string]Repo, len(d.Repos)),
		repoByPath: make(map[string]string, len(d.Repos)),
		grants:     make(map[grantKey]Level, len(d.Grants)),
		trusts:     append([]WorkloadTrust(nil), d.Trusts...),
	}
	for _, id := range d.Identities {
		if id.ID == "" {
			return nil, fmt.Errorf("datastore: identity with empty id")
		}
		if !validKind(id.Kind) {
			return nil, fmt.Errorf("datastore: identity %q has unknown kind %q", id.ID, id.Kind)
		}
		if _, dup := s.identities[id.ID]; dup {
			return nil, fmt.Errorf("datastore: duplicate identity %q", id.ID)
		}
		s.identities[id.ID] = id
	}
	for _, k := range d.Keys {
		if !validFingerprint(k.Fingerprint) {
			return nil, fmt.Errorf("datastore: malformed fingerprint %q", k.Fingerprint)
		}
		if _, ok := s.identities[k.IdentityID]; !ok {
			return nil, fmt.Errorf("datastore: key %q references unknown identity %q", k.Fingerprint, k.IdentityID)
		}
		if _, dup := s.keys[k.Fingerprint]; dup {
			return nil, fmt.Errorf("datastore: fingerprint %q maps to more than one identity", k.Fingerprint)
		}
		s.keys[k.Fingerprint] = k
	}
	for _, r := range d.Repos {
		if !repoIDPattern.MatchString(r.ID) {
			return nil, fmt.Errorf("datastore: repo id %q is not letters, digits, hyphens and underscores", r.ID)
		}
		if _, dup := s.repos[r.ID]; dup {
			return nil, fmt.Errorf("datastore: duplicate repo %q", r.ID)
		}
		s.repos[r.ID] = r
		for _, p := range append([]string{r.Path}, r.Aliases...) {
			// Client paths are normalized before lookup, so a stored path that
			// is not already canonical could never match and would deny the
			// repo silently.
			if canon, err := pathnorm.Normalize(p); err != nil || canon != p {
				return nil, fmt.Errorf("datastore: repo %q path %q is not canonical", r.ID, p)
			}
			if other, dup := s.repoByPath[p]; dup {
				return nil, fmt.Errorf("datastore: path %q claimed by repos %q and %q", p, other, r.ID)
			}
			s.repoByPath[p] = r.ID
		}
	}
	for _, g := range d.Grants {
		if _, ok := s.identities[g.IdentityID]; !ok {
			return nil, fmt.Errorf("datastore: grant references unknown identity %q", g.IdentityID)
		}
		if _, ok := s.repos[g.RepoID]; !ok {
			return nil, fmt.Errorf("datastore: grant references unknown repo %q", g.RepoID)
		}
		if g.Level < LevelRead || g.Level > LevelAdmin {
			return nil, fmt.Errorf("datastore: grant for %q on %q has invalid level %v", g.IdentityID, g.RepoID, g.Level)
		}
		gk := grantKey{g.IdentityID, g.RepoID}
		if _, dup := s.grants[gk]; dup {
			return nil, fmt.Errorf("datastore: duplicate grant for %q on %q", g.IdentityID, g.RepoID)
		}
		s.grants[gk] = g.Level
	}
	for _, t := range d.Trusts {
		if t.Issuer == "" || t.Audience == "" || t.RepoClaim == "" {
			return nil, fmt.Errorf("datastore: trust entry with empty issuer, audience or repo claim")
		}
		if !json.Valid([]byte(t.JWKS)) {
			return nil, fmt.Errorf("datastore: trust entry for %q has no valid JWKS", t.Issuer)
		}
		if t.MaxLevel != LevelRead {
			return nil, fmt.Errorf("datastore: trust entry for %q has max level %v, want read", t.Issuer, t.MaxLevel)
		}
	}
	return s, nil
}

func validKind(k IdentityKind) bool {
	return k == KindPerson || k == KindDeployKey || k == KindWorkload
}

// validFingerprint accepts exactly what ssh.FingerprintSHA256 produces:
// "SHA256:" and the unpadded standard base64 of a 32-byte digest.
func validFingerprint(fp string) bool {
	b64, ok := strings.CutPrefix(fp, "SHA256:")
	if !ok {
		return false
	}
	raw, err := base64.RawStdEncoding.Strict().DecodeString(b64)
	return err == nil && len(raw) == 32
}

// Data returns the snapshot's content, in no particular order. NewSnapshot
// accepts it and builds an equal snapshot.
func (s *Snapshot) Data() Data {
	d := Data{
		Meta:       s.meta,
		Identities: slices.Collect(maps.Values(s.identities)),
		Keys:       slices.Collect(maps.Values(s.keys)),
		Repos:      slices.Collect(maps.Values(s.repos)),
		Trusts:     s.Trusts(),
	}
	for k, l := range s.grants {
		d.Grants = append(d.Grants, Grant{IdentityID: k.identityID, RepoID: k.repoID, Level: l})
	}
	return d
}

// Meta returns the snapshot's metadata.
func (s *Snapshot) Meta() Meta { return s.meta }

// KeyOwner returns the active identity that owns fingerprint. Inactive or
// unknown identities are reported as absent.
func (s *Snapshot) KeyOwner(fingerprint string) (Identity, bool) {
	k, ok := s.keys[fingerprint]
	if !ok {
		return Identity{}, false
	}
	id, ok := s.identities[k.IdentityID]
	if !ok || !id.Active {
		return Identity{}, false
	}
	return id, true
}

// Identity returns the identity with the given ID if it exists and is active.
func (s *Snapshot) Identity(id string) (Identity, bool) {
	i, ok := s.identities[id]
	if !ok || !i.Active {
		return Identity{}, false
	}
	return i, true
}

// KeyHolder returns the ID of the identity that holds fingerprint, active or
// not. It is for audit records, which tell a removed member apart from a
// stranger; access decisions use KeyOwner, which treats both as absent.
func (s *Snapshot) KeyHolder(fingerprint string) (string, bool) {
	k, ok := s.keys[fingerprint]
	return k.IdentityID, ok
}

// Deactivated reports whether the identity exists but is inactive. Like
// KeyHolder it is for audit records, never for access decisions.
func (s *Snapshot) Deactivated(id string) bool {
	i, ok := s.identities[id]
	return ok && !i.Active
}

// RepoByPath resolves a canonical path or alias to a repo.
func (s *Snapshot) RepoByPath(path string) (Repo, bool) {
	id, ok := s.repoByPath[path]
	if !ok {
		return Repo{}, false
	}
	return s.repos[id], true
}

// Repo returns the repo with the given ID.
func (s *Snapshot) Repo(id string) (Repo, bool) {
	r, ok := s.repos[id]
	return r, ok
}

// GrantLevel returns the level the identity holds on the repo, LevelNone if no
// grant exists.
func (s *Snapshot) GrantLevel(identityID, repoID string) Level {
	return s.grants[grantKey{identityID, repoID}]
}

// Trusts returns a copy of the workload-trust entries.
func (s *Snapshot) Trusts() []WorkloadTrust {
	return append([]WorkloadTrust(nil), s.trusts...)
}

// GrantRef names one grant.
type GrantRef struct {
	IdentityID string
	RepoID     string
}

// Narrowing is a change that can only remove access: revoke keys, deactivate
// identities, drop grants. Deltas from webhooks are expressed this way, so a
// forged-but-signed or replayed webhook can at worst deny access; widening
// access happens only through a full sync.
type Narrowing struct {
	RevokeKeys           []string
	DeactivateIdentities []string
	DropGrants           []GrantRef
}

// narrowed returns a copy of s with n applied. Unknown keys, identities and
// grants are ignored: they already have no access.
func (s *Snapshot) narrowed(n Narrowing) *Snapshot {
	c := *s
	c.keys = maps.Clone(s.keys)
	c.identities = maps.Clone(s.identities)
	c.grants = maps.Clone(s.grants)
	for _, fp := range n.RevokeKeys {
		delete(c.keys, fp)
	}
	for _, id := range n.DeactivateIdentities {
		if i, ok := c.identities[id]; ok {
			i.Active = false
			c.identities[id] = i
		}
	}
	for _, g := range n.DropGrants {
		delete(c.grants, grantKey{g.IdentityID, g.RepoID})
	}
	return &c
}
