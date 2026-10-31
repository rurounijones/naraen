package telemetry

import (
	"context"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Span attribute keys. They name what the audit log records name, under the
// lfs. prefix, so a trace is found by the same identity, repo or token ID as
// its log lines. Unlike metric labels they may hold unbounded values such as
// object IDs and request IDs.
const (
	AttrIdentity     = "lfs.identity"
	AttrIdentityType = "lfs.identity_type"
	AttrFingerprint  = "lfs.fingerprint"
	AttrRepo         = "lfs.repo"
	AttrRepoID       = "lfs.repo_id"
	AttrOperation    = "lfs.operation"
	AttrCommand      = "lfs.command"
	AttrTokenID      = "lfs.token_id" // #nosec G101 -- an attribute name; the token ID is not a credential
	AttrRequestID    = "lfs.request_id"
	AttrReason       = "lfs.reason"
	AttrOID          = "lfs.oid"
	AttrSize         = "lfs.size"
	AttrOutcome      = "lfs.outcome"
	AttrIssuer       = "lfs.issuer"
	AttrProvider     = "lfs.provider"
	AttrEvent        = "lfs.event"
	AttrDelivery     = "lfs.delivery"
	AttrObjects      = "lfs.objects"
	AttrLinks        = "lfs.links"
	AttrBytes        = "lfs.bytes"
)

// Tracer returns the server's tracer from tp, for spans that start a trace:
// an SSH connection or a provider sync. HTTP requests start theirs in
// otelhttp, with HTTPOptions.
func Tracer(tp trace.TracerProvider) trace.Tracer { return tp.Tracer(scopeName) }

// Start starts a span named name as a child of the span in ctx, from that
// span's provider, so request-path code needs no tracer of its own. Without a
// span in ctx the new span records nothing.
func Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return Tracer(trace.SpanFromContext(ctx).TracerProvider()).Start(ctx, name, trace.WithAttributes(attrs...))
}

// Annotate adds attrs to the span in ctx.
func Annotate(ctx context.Context, attrs ...attribute.KeyValue) {
	trace.SpanFromContext(ctx).SetAttributes(attrs...)
}

// HTTPOptions configures otelhttp for the HTTPS listener and for outgoing
// requests: spans from tp, and trace context neither read from nor sent to
// the other side. Callers of the listener are untrusted, so a traceparent
// header they send must not choose the trace a request joins; GitHub and S3
// have no use for ours. otelhttp's own metrics are left off, so the metrics
// the server exports are exactly the ones this package names.
func HTTPOptions(tp trace.TracerProvider) []otelhttp.Option {
	return []otelhttp.Option{
		otelhttp.WithTracerProvider(tp),
		otelhttp.WithPropagators(propagation.NewCompositeTextMapPropagator()),
		otelhttp.WithMeterProvider(noop.NewMeterProvider()),
	}
}
