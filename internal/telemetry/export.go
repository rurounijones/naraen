package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// ExportInterval is how often metrics are pushed. Alerts work on windows of 5
// to 15 minutes, so 15 seconds is real time for them while keeping the
// exporter's traffic small.
const ExportInterval = 15 * time.Second

// Export configures where metrics, traces and logs go.
type Export struct {
	// Endpoint is the OTLP/HTTP base URL; metrics go to Endpoint/v1/metrics,
	// traces to Endpoint/v1/traces and logs to Endpoint/v1/logs. Empty
	// disables export: the instruments and spans still work, logs go to the
	// local handler only, and nothing leaves the process.
	Endpoint string
	Headers  map[string]string
	// Version is reported as service.version.
	Version string
}

// Providers holds the OpenTelemetry pipelines. The caller must Shutdown it to
// flush the last metrics interval and any queued spans and log records.
type Providers struct {
	Meter *sdkmetric.MeterProvider
	// Tracer samples every span: the server handles a few control requests
	// per transfer, so tracing all of them costs little, and a trace that was
	// sampled away cannot help an investigation.
	Tracer *sdktrace.TracerProvider
	// logger is nil when logs are not exported.
	logger *sdklog.LoggerProvider
}

// New returns providers that push to e.Endpoint: metrics every
// ExportInterval, spans and logs in batches. All three retry from bounded
// in-memory queues and drop when those fill, so a collector outage never
// blocks a request.
func New(ctx context.Context, e Export) (*Providers, error) {
	res := resource.NewSchemaless(
		attribute.String("service.name", "naraen"),
		attribute.String("service.version", e.Version))
	sampler := sdktrace.WithSampler(sdktrace.AlwaysSample())
	if e.Endpoint == "" {
		// Spans are still made without export, so local log records of one
		// request share a trace ID.
		return &Providers{
			Meter:  sdkmetric.NewMeterProvider(sdkmetric.WithResource(res)),
			Tracer: sdktrace.NewTracerProvider(sdktrace.WithResource(res), sampler),
		}, nil
	}
	mexp, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(e.Endpoint+"/v1/metrics"),
		otlpmetrichttp.WithHeaders(e.Headers))
	if err != nil {
		return nil, fmt.Errorf("telemetry: otlp metrics exporter: %w", err)
	}
	texp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(e.Endpoint+"/v1/traces"),
		otlptracehttp.WithHeaders(e.Headers))
	if err != nil {
		return nil, fmt.Errorf("telemetry: otlp traces exporter: %w", err)
	}
	lexp, err := otlploghttp.New(ctx,
		otlploghttp.WithEndpointURL(e.Endpoint+"/v1/logs"),
		otlploghttp.WithHeaders(e.Headers))
	if err != nil {
		return nil, fmt.Errorf("telemetry: otlp logs exporter: %w", err)
	}
	return &Providers{
		Meter: sdkmetric.NewMeterProvider(sdkmetric.WithResource(res),
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(mexp, sdkmetric.WithInterval(ExportInterval)))),
		Tracer: sdktrace.NewTracerProvider(sdktrace.WithResource(res), sampler, sdktrace.WithBatcher(texp)),
		logger: sdklog.NewLoggerProvider(sdklog.WithResource(res),
			sdklog.WithProcessor(sdklog.NewBatchProcessor(lexp))),
	}, nil
}

// LogHandler returns a handler that writes every record to local and, when
// logs are exported, also to OpenTelemetry. Export is held to local's level,
// so the backend receives exactly the records the local log does. Local
// records made in a span carry its trace_id and span_id; exported records
// carry them in their own trace fields, which the bridge fills in.
func (p *Providers) LogHandler(local slog.Handler) slog.Handler {
	local = traced{local}
	if p.logger == nil {
		return local
	}
	return slog.NewMultiHandler(local,
		leveled{otelslog.NewHandler(scopeName, otelslog.WithLoggerProvider(p.logger)), local})
}

// Shutdown flushes and stops every pipeline.
func (p *Providers) Shutdown(ctx context.Context) error {
	err := errors.Join(p.Meter.Shutdown(ctx), p.Tracer.Shutdown(ctx))
	if p.logger != nil {
		err = errors.Join(err, p.logger.Shutdown(ctx))
	}
	return err
}

// traced adds the IDs of the span a record was made in, so the local log
// lines of one request can be found together and beside its trace. Inside a
// group the IDs land in that group too; the server's loggers use none.
type traced struct{ slog.Handler }

func (t traced) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		// The record may be passed on to other handlers, so it is changed
		// only as a copy.
		r = r.Clone()
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return t.Handler.Handle(ctx, r)
}

func (t traced) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traced{t.Handler.WithAttrs(attrs)}
}

func (t traced) WithGroup(name string) slog.Handler {
	return traced{t.Handler.WithGroup(name)}
}

// leveled passes on only the records that level would also accept.
type leveled struct {
	slog.Handler
	level slog.Handler
}

func (l leveled) Enabled(ctx context.Context, lv slog.Level) bool {
	return l.level.Enabled(ctx, lv) && l.Handler.Enabled(ctx, lv)
}

func (l leveled) WithAttrs(attrs []slog.Attr) slog.Handler {
	return leveled{l.Handler.WithAttrs(attrs), l.level}
}

func (l leveled) WithGroup(name string) slog.Handler {
	return leveled{l.Handler.WithGroup(name), l.level}
}

// ErrorHandler reports export failures through the server's log. Without it
// OpenTelemetry writes them to its own logger, outside the JSON log stream.
// Give it the local logger only: a failed log export reported through the
// exporting logger would queue yet another record for the failing backend.
// A failure never affects a request; the CloudWatch heartbeat alarm notices
// when metrics stop arriving.
func ErrorHandler(log *slog.Logger) otel.ErrorHandler {
	return otel.ErrorHandlerFunc(func(err error) {
		log.Warn("telemetry export failed", "error", err)
	})
}
