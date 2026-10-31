package provider

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/telemetry"
)

// Run keeps store in step with p: a full sync at once, then one every
// interval, until ctx is done. A failed or rejected sync leaves the live
// snapshot in place; the store's staleness limit, not this loop, decides
// when serving from it must stop.
func Run(ctx context.Context, p Provider, store *datastore.Store, interval time.Duration, rec *telemetry.Recorder, log *slog.Logger) {
	log = log.With("provider", p.Name())
	sync := func() {
		// Freshness counts from before the source is read.
		start := store.StartSync()
		snap, err := p.FullSync(ctx)
		if err != nil {
			log.ErrorContext(ctx, "full sync failed", "error", err)
			reason := telemetry.SyncFailed
			if errors.Is(err, ErrRateLimited) {
				reason = telemetry.SyncRateLimited
			}
			rec.SyncFailure(ctx, reason)
			return
		}
		if err := store.Swap(start, snap); err != nil {
			log.ErrorContext(ctx, "full sync rejected", "error", err)
			rec.SyncFailure(ctx, telemetry.SyncRejected)
			return
		}
		log.InfoContext(ctx, "full sync applied", "synced_at", snap.Meta().SyncedAt)
	}
	sync()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sync()
		}
	}
}
