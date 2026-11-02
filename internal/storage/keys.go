// Package storage holds S3 object naming and the pre-signing contract.
package storage

import (
	"context"
	"time"

	"github.com/rurounijones/naraen/internal/oid"
)

// ObjectKey returns the S3 key for an object:
// {repoID}/{oid[0:2]}/{oid[2:4]}/{oid}. Each repo has one top-level folder,
// named by its stable ID, so a rename moves nothing and lifecycle rules can
// address a repo by prefix.
// Taking an oid.OID means an unvalidated string can never reach a key.
func ObjectKey(repoID string, id oid.OID) string {
	s := string(id)
	return repoID + "/" + s[0:2] + "/" + s[2:4] + "/" + s
}

// SnapshotKey is where the bucket holds the saved datastore snapshot. It covers
// every repo, so it sits at the bucket's root, not in a repo's folder. It has no
// slash, so no ObjectKey can ever equal it, and no client can get a link to it.
const SnapshotKey = "access-permissions-snapshot.json"

// Link is a pre-signed URL and the headers the client must send with it.
type Link struct {
	URL     string
	Headers map[string]string
	Expires time.Time
}

// LinkTTL is how long a pre-signed URL stays valid. S3 checks a link only when
// a transfer starts, so a large transfer still completes after it expires.
const LinkTTL = 15 * time.Minute

// Presigner issues pre-signed URLs valid for LinkTTL and reports what a repo
// already has stored. Upload links sign the SHA-256 checksum and content
// length so S3 rejects bytes that do not match the OID. requestID is carried in each URL
// so S3's access logs tie a transfer to the request that authorized it.
type Presigner interface {
	PresignGet(ctx context.Context, repoID string, id oid.OID, requestID string) (Link, error)
	PresignPut(ctx context.Context, repoID string, id oid.OID, size int64, requestID string) (Link, error)
	// Stat returns the stored size of an object, or found false if the
	// repo does not have it stored.
	Stat(ctx context.Context, repoID string, id oid.OID) (size int64, found bool, err error)
}
