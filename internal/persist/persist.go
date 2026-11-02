// Package persist keeps a signed copy of the live datastore snapshot in the
// bucket, so a replacement server can serve while the provider's source is
// unreachable, rather than refusing everything until a sync succeeds.
//
// Writing to the bucket must not be enough to grant access, so the copy is
// signed with the server's token keys, and its age still counts from when the
// sync that built it began: a restart never extends the staleness limit.
package persist

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/storage"
	"github.com/rurounijones/naraen/internal/telemetry"
	"github.com/rurounijones/naraen/internal/token"
)

const (
	// domain separates these MACs from bearer tokens signed with the same keys.
	domain = "naraen datastore snapshot v1\x00"
	// restoreTimeout bounds startup's wait for the bucket. A server that gives
	// up only stays not-ready until its first sync, as with no saved copy.
	restoreTimeout = 10 * time.Second
	// saveTimeout bounds one write, so a hung one cannot hold up later ones.
	saveTimeout = 30 * time.Second
)

var errInvalid = errors.New("persist: signature does not verify")

// Objects reads and writes whole objects in the bucket.
type Objects interface {
	ReadObject(ctx context.Context, key string) (body []byte, found bool, err error)
	WriteObject(ctx context.Context, key string, body []byte) error
}

// saved is what the signature covers. Began is the sync's start by the clock
// of the server that ran it.
type saved struct {
	Began time.Time      `json:"began"`
	Data  datastore.Data `json:"data"`
}

type envelope struct {
	KeyID   string `json:"key_id"`
	Payload []byte `json:"payload"`
	MAC     []byte `json:"mac"`
}

func mac(k token.Key, payload []byte) []byte {
	m := hmac.New(sha256.New, k.Secret)
	m.Write([]byte(domain + k.ID + "\x00"))
	m.Write(payload)
	return m.Sum(nil)
}

// seal signs snap with keys[0], the key that mints tokens.
func seal(keys []token.Key, snap *datastore.Snapshot, began time.Time) ([]byte, error) {
	payload, err := json.Marshal(saved{Began: began, Data: snap.Data()})
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{KeyID: keys[0].ID, Payload: payload, MAC: mac(keys[0], payload)})
}

// open verifies raw against any of keys, so a copy signed before a rotation is
// still accepted while its key stays listed, and rebuilds the snapshot.
func open(keys []token.Key, raw []byte) (*datastore.Snapshot, time.Time, error) {
	var e envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, time.Time{}, err
	}
	for _, k := range keys {
		if k.ID != e.KeyID || !hmac.Equal(mac(k, e.Payload), e.MAC) {
			continue
		}
		var s saved
		if err := json.Unmarshal(e.Payload, &s); err != nil {
			return nil, time.Time{}, err
		}
		snap, err := datastore.NewSnapshot(s.Data)
		return snap, s.Began, err
	}
	return nil, time.Time{}, errInvalid
}

// Restore publishes the saved copy, if there is one that verifies and is
// within the staleness limit. It must run before the provider starts. Any
// failure leaves the store as it was, so the server fails closed until a sync
// succeeds; none stops the server, since that sync may well succeed.
func Restore(ctx context.Context, store *datastore.Store, objects Objects, keys []token.Key, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(ctx, restoreTimeout)
	defer cancel()
	raw, found, err := objects.ReadObject(ctx, storage.SnapshotKey)
	if err != nil {
		log.WarnContext(ctx, "saved datastore snapshot could not be read", "error", err)
		return
	}
	if !found {
		log.InfoContext(ctx, "no saved datastore snapshot")
		return
	}
	snap, began, err := open(keys, raw)
	if err != nil {
		log.WarnContext(ctx, "saved datastore snapshot refused", "error", err)
		return
	}
	if err := store.Restore(snap, began); err != nil {
		log.WarnContext(ctx, "saved datastore snapshot refused", "error", err)
		return
	}
	log.InfoContext(ctx, "datastore restored from saved snapshot", "began", began)
}

// Run saves the live snapshot each time it changes, until ctx is done. A
// narrowing is saved as well as a full sync, or a restart could hand back
// access that a webhook had removed. Changes made during a save coalesce into
// one more save. A failed save is not retried: the next change writes the
// whole snapshot again.
func Run(ctx context.Context, store *datastore.Store, objects Objects, keys []token.Key, tp trace.TracerProvider, rec *telemetry.Recorder, log *slog.Logger) {
	tracer := telemetry.Tracer(tp)
	for {
		select {
		case <-ctx.Done():
			return
		case <-store.Changed():
			save(ctx, tracer, store, objects, keys, rec, log)
		}
	}
}

func save(ctx context.Context, tracer trace.Tracer, store *datastore.Store, objects Objects, keys []token.Key, rec *telemetry.Recorder, log *slog.Logger) {
	ctx, span := tracer.Start(ctx, "datastore snapshot save")
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, saveTimeout)
	defer cancel()
	snap, began, ok := store.Latest()
	if !ok {
		return
	}
	body, err := seal(keys, snap, began)
	if err == nil {
		err = objects.WriteObject(ctx, storage.SnapshotKey, body)
	}
	if err != nil {
		log.ErrorContext(ctx, "datastore snapshot not saved", "error", err)
		rec.SnapshotSaveFailure(ctx)
		span.RecordError(err)
		span.SetStatus(codes.Error, "datastore snapshot not saved")
		return
	}
	log.InfoContext(ctx, "datastore snapshot saved", "began", began)
}
