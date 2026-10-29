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

// Link is a pre-signed URL and the headers the client must send with it.
type Link struct {
	URL     string
	Headers map[string]string
	Expires time.Time
}

// Presigner issues 15-minute pre-signed URLs. Upload links sign the SHA-256
// checksum and content length so S3 rejects bytes that do not match the OID.
type Presigner interface {
	PresignGet(ctx context.Context, repoID string, id oid.OID, requestID string) (Link, error)
	PresignPut(ctx context.Context, repoID string, id oid.OID, size int64, requestID string) (Link, error)
}
