// Package batch parses and validates Git LFS Batch API requests.
package batch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/oid"
)

const (
	// MaxBodyBytes bounds the request body.
	MaxBodyBytes = 1 << 20
	// MaxObjects bounds the objects in one batch.
	MaxObjects = 1000
	// MaxObjectSize is the largest object a single pre-signed PUT can carry (5 GB).
	MaxObjectSize = 5 << 30
)

// ErrInvalid is returned for any request that fails validation.
var ErrInvalid = errors.New("batch: invalid request")

// Object identifies one LFS object.
type Object struct {
	OID  oid.OID
	Size int64
}

// Request is a validated Batch API request.
type Request struct {
	Operation lfs.Operation
	Objects   []Object
}

type wireRequest struct {
	Operation string   `json:"operation"`
	Transfers []string `json:"transfers"`
	HashAlgo  *string  `json:"hash_algo"`
	Objects   []struct {
		OID  string `json:"oid"`
		Size int64  `json:"size"`
	} `json:"objects"`
}

// ParseRequest reads and validates a Batch API request body. Unknown fields
// (such as ref) are ignored; known ones are strict. The client must accept the
// basic transfer adapter and SHA-256 OIDs if it names any, because those are
// the only ones the server offers. Repeated objects are merged, so they cannot
// inflate the work or the download budget of one request; the same OID with
// two sizes is refused.
func ParseRequest(r io.Reader) (Request, error) {
	// Read one byte past the cap so an oversized body is rejected outright
	// rather than silently truncated.
	raw, err := io.ReadAll(io.LimitReader(r, MaxBodyBytes+1))
	if err != nil || len(raw) > MaxBodyBytes {
		return Request{}, fmt.Errorf("%w: body", ErrInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var w wireRequest
	if err := dec.Decode(&w); err != nil {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if dec.More() {
		return Request{}, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	op, err := lfs.ParseOperation(w.Operation)
	if err != nil {
		return Request{}, ErrInvalid
	}
	// Absent means basic; present must include it.
	if w.Transfers != nil && !slices.Contains(w.Transfers, "basic") {
		return Request{}, fmt.Errorf("%w: transfers", ErrInvalid)
	}
	if w.HashAlgo != nil && *w.HashAlgo != "sha256" {
		return Request{}, fmt.Errorf("%w: hash_algo", ErrInvalid)
	}
	if len(w.Objects) == 0 || len(w.Objects) > MaxObjects {
		return Request{}, fmt.Errorf("%w: object count", ErrInvalid)
	}
	req := Request{Operation: op, Objects: make([]Object, 0, len(w.Objects))}
	sizes := make(map[oid.OID]int64, len(w.Objects))
	for _, o := range w.Objects {
		id, err := oid.Parse(o.OID)
		if err != nil {
			return Request{}, ErrInvalid
		}
		if o.Size < 0 || o.Size > MaxObjectSize {
			return Request{}, fmt.Errorf("%w: size", ErrInvalid)
		}
		if size, seen := sizes[id]; seen {
			if size != o.Size {
				return Request{}, fmt.Errorf("%w: conflicting sizes for one oid", ErrInvalid)
			}
			continue
		}
		sizes[id] = o.Size
		req.Objects = append(req.Objects, Object{OID: id, Size: o.Size})
	}
	return req, nil
}
