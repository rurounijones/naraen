// Package provider defines the contract between an authorization source (GitHub
// first) and the datastore. A provider's only output is writes to the datastore:
// it never signs tokens, issues S3 URLs or sees request-path credentials.
package provider

import (
	"context"

	"github.com/rurounijones/naraen/internal/datastore"
)

// Provider builds snapshots from a source service.
type Provider interface {
	// Name identifies the provider in snapshot metadata and logs.
	Name() string
	// FullSync builds a complete new snapshot off to the side.
	FullSync(ctx context.Context) (*datastore.Snapshot, error)
}
