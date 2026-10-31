package provider

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/telemetry"
)

// Run keeps store in step with p: a full sync at once, then one every
// interval, until ctx is done. A failed or rejected sync leaves the live
// snapshot in place; the store's staleness limit, not this loop, decides
// when serving from it must stop. Each sync is a trace of its own from tp,
// which holds the provider's requests to its source.
func Run(ctx context.Context, p Provider, store *datastore.Store, interval time.Duration, tp trace.TracerProvider, rec *telemetry.Recorder, log *slog.Logger) {
	log = log.With("provider", p.Name())
	tracer := telemetry.Tracer(tp)
	sync := func() {
		ctx, span := tracer.Start(ctx, "provider full sync",
			trace.WithAttributes(attribute.String(telemetry.AttrProvider, p.Name())))
		defer span.End()
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
			fail(span, reason, err)
			return
		}
		if err := store.Swap(start, snap); err != nil {
			log.ErrorContext(ctx, "full sync rejected", "error", err)
			rec.SyncFailure(ctx, telemetry.SyncRejected)
			fail(span, telemetry.SyncRejected, err)
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

// fail marks a sync's span as failed, for reason, the label its
// lfs.sync.failures count carries.
func fail(span trace.Span, reason string, err error) {
	span.SetAttributes(attribute.String(telemetry.AttrReason, reason))
	span.RecordError(err)
	span.SetStatus(codes.Error, "full sync "+reason)
}
