package datastore

import (
	"encoding/json"
	"fmt"
	"io"
)

// maxSnapshotFile bounds snapshot files read from disk.
const maxSnapshotFile = 64 << 20

// ParseSnapshot reads a JSON-encoded Data document and indexes it. It is used to
// load snapshots from files for tests and local development, with no provider.
func ParseSnapshot(r io.Reader) (*Snapshot, error) {
	dec := json.NewDecoder(io.LimitReader(r, maxSnapshotFile))
	dec.DisallowUnknownFields()
	var d Data
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("datastore: decode snapshot: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("datastore: trailing data after snapshot")
	}
	return NewSnapshot(d)
}
