package telemetry

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// collect returns every counter data point the reader holds, keyed by metric
// name and then by the point's attributes. Float counters are truncated, so
// tests give them values that add up to whole numbers.
func collect(t *testing.T, r sdkmetric.Reader) map[string]map[attribute.Distinct]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[attribute.Distinct]int64{}
	for _, sm := range rm.ScopeMetrics {
		if sm.Scope.Name != scopeName {
			t.Errorf("scope = %q", sm.Scope.Name)
		}
		for _, m := range sm.Metrics {
			got[m.Name] = map[attribute.Distinct]int64{}
			switch sum := m.Data.(type) {
			case metricdata.Sum[int64]:
				if !sum.IsMonotonic {
					t.Fatalf("%s is not monotonic", m.Name)
				}
				for _, dp := range sum.DataPoints {
					got[m.Name][dp.Attributes.Equivalent()] = dp.Value
				}
			case metricdata.Sum[float64]:
				if !sum.IsMonotonic {
					t.Fatalf("%s is not monotonic", m.Name)
				}
				for _, dp := range sum.DataPoints {
					got[m.Name][dp.Attributes.Equivalent()] = int64(dp.Value)
				}
			default:
				t.Fatalf("%s is %T, want a monotonic sum", m.Name, m.Data)
			}
		}
	}
	return got
}

func set(kv ...string) attribute.Distinct {
	var attrs []attribute.KeyValue
	for i := 0; i < len(kv); i += 2 {
		attrs = append(attrs, attribute.String(kv[i], kv[i+1]))
	}
	s := attribute.NewSet(attrs...)
	return s.Equivalent()
}

func TestRecorder(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	r := NewRecorder(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	ctx := context.Background()
	r.AuthFailure(ctx, "unknown_key", IdentityTypeUnknown)
	r.AuthFailure(ctx, "unknown_key", IdentityTypeUnknown)
	r.AuthFailure(ctx, "insufficient_grant", "person")
	r.TokenIssued(ctx, "upload", "1", "alice")
	r.ConnectionRejected(ctx, "rate")
	r.LinkOutcome(ctx, "download", "1", "alice", OutcomeIssued)
	r.LinkOutcome(ctx, "download", "1", "alice", OutcomeIssued)
	r.LinkOutcome(ctx, "download", "1", "alice", OutcomeMissing)
	r.BytesRequested(ctx, "download", "1", "alice", 300)
	r.SyncFailure(ctx, "rejected")
	r.RateLimitWait(ctx, 90*time.Second)
	r.RateLimitWait(ctx, 1500*time.Millisecond)
	r.RateLimitWait(ctx, 500*time.Millisecond)

	got := collect(t, reader)
	want := map[string]map[attribute.Distinct]int64{
		MetricAuthFailures: {
			set(LabelReason, "unknown_key", LabelIdentityType, "unknown"):       2,
			set(LabelReason, "insufficient_grant", LabelIdentityType, "person"): 1,
		},
		MetricTokensIssued:     {set(LabelOperation, "upload", LabelRepo, "1", LabelUser, "alice"): 1},
		MetricSSHConnsRejected: {set(LabelReason, "rate"): 1},
		MetricLinksIssued: {
			set(LabelOperation, "download", LabelRepo, "1", LabelUser, "alice", LabelOutcome, "issued"):  2,
			set(LabelOperation, "download", LabelRepo, "1", LabelUser, "alice", LabelOutcome, "missing"): 1,
		},
		MetricBytesRequested:    {set(LabelOperation, "download", LabelRepo, "1", LabelUser, "alice"): 300},
		MetricSyncFailures:      {set(LabelReason, "rejected"): 1},
		MetricSyncRateLimitWait: {set(): 92},
	}
	if len(got) != len(want) {
		t.Fatalf("metrics = %v", got)
	}
	for name, points := range want {
		if len(got[name]) != len(points) {
			t.Errorf("%s points = %v", name, got[name])
		}
		for attrs, v := range points {
			if got[name][attrs] != v {
				t.Errorf("%s%v = %d, want %d", name, attrs, got[name][attrs], v)
			}
		}
	}
}

// receiver is a minimal OTLP/HTTP endpoint that records each push.
type receiver struct {
	mu      sync.Mutex
	headers map[string]http.Header // by path, from the latest push
	logs    []string               // every log record as "LEVEL msg k=v ..."
	// logTraces holds each log record's trace ID, hex, "" for none.
	logTraces []string
	spans     []*tracepb.Span
}

func (rc *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.headers[r.URL.Path] = r.Header.Clone()
	var req collectorlogs.ExportLogsServiceRequest
	if strings.HasSuffix(r.URL.Path, "/v1/logs") && proto.Unmarshal(body, &req) == nil {
		for _, rl := range req.GetResourceLogs() {
			for _, sl := range rl.GetScopeLogs() {
				for _, lr := range sl.GetLogRecords() {
					rec := []string{lr.GetSeverityText(), lr.GetBody().GetStringValue()}
					rc.logs = append(rc.logs, strings.Join(flatten(rec, "", lr.GetAttributes()), " "))
					rc.logTraces = append(rc.logTraces, hex.EncodeToString(lr.GetTraceId()))
				}
			}
		}
	}
	var treq collectortrace.ExportTraceServiceRequest
	if strings.HasSuffix(r.URL.Path, "/v1/traces") && proto.Unmarshal(body, &treq) == nil {
		for _, rs := range treq.GetResourceSpans() {
			for _, ss := range rs.GetScopeSpans() {
				rc.spans = append(rc.spans, ss.GetSpans()...)
			}
		}
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
}

// flatten appends attributes as "k=v", with a group's members as "group.k=v".
func flatten(out []string, prefix string, attrs []*commonpb.KeyValue) []string {
	for _, kv := range attrs {
		if group := kv.GetValue().GetKvlistValue(); group != nil {
			out = flatten(out, prefix+kv.GetKey()+".", group.GetValues())
			continue
		}
		out = append(out, prefix+kv.GetKey()+"="+kv.GetValue().GetStringValue())
	}
	return out
}

func newReceiver(t *testing.T) (*receiver, string) {
	t.Helper()
	rc := &receiver{headers: map[string]http.Header{}}
	srv := httptest.NewServer(rc)
	t.Cleanup(srv.Close)
	return rc, srv.URL
}

// Metrics, traces and logs go to their paths under the configured base URL
// with the configured headers, and Shutdown flushes what was recorded since
// the last push. Logs reach the local handler too, and the backend receives
// exactly the records the local handler accepts. A record made in a span
// carries the span's trace: locally as attributes, exported in the record's
// own trace field.
func TestNewExports(t *testing.T) {
	rc, url := newReceiver(t)
	p, err := New(context.Background(), Export{
		Endpoint: url + "/api/default",
		Headers:  map[string]string{"Authorization": "Basic c2VjcmV0"},
		Version:  "1.2.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	NewRecorder(p.Meter).TokenIssued(context.Background(), "download", "1", "alice")
	ctx, span := Tracer(p.Tracer).Start(context.Background(), "ssh exec")
	var local bytes.Buffer
	log := slog.New(p.LogHandler(slog.NewJSONHandler(&local, nil))).With("identity", "alice")
	log.Debug("below the local level")
	log.WithGroup("g").InfoContext(ctx, "token issued", "repo", "acme/assets")
	log.Info("outside a span")
	span.End()
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()
	for _, path := range []string{"/api/default/v1/metrics", "/api/default/v1/traces", "/api/default/v1/logs"} {
		if h, ok := rc.headers[path]; !ok || h.Get("Authorization") != "Basic c2VjcmV0" {
			t.Errorf("%s: pushed %v with headers %v", path, ok, h)
		}
	}
	traceID := span.SpanContext().TraceID().String()
	if len(rc.spans) != 1 || rc.spans[0].GetName() != "ssh exec" || hex.EncodeToString(rc.spans[0].GetTraceId()) != traceID {
		t.Errorf("exported spans = %v", rc.spans)
	}
	if want := []string{"INFO token issued identity=alice g.repo=acme/assets", "INFO outside a span identity=alice"}; !slices.Equal(rc.logs, want) {
		t.Errorf("exported logs = %q, want %q", rc.logs, want)
	}
	// The bridge sets the trace field, so the IDs are not repeated as
	// attributes on exported records.
	if want := []string{traceID, ""}; !slices.Equal(rc.logTraces, want) {
		t.Errorf("exported log traces = %q, want %q", rc.logTraces, want)
	}
	lines := strings.Split(strings.TrimSpace(local.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"trace_id":"`+traceID+`"`) ||
		!strings.Contains(lines[0], `"span_id":"`+span.SpanContext().SpanID().String()+`"`) || strings.Contains(lines[1], "trace_id") {
		t.Errorf("local log = %s", local.String())
	}
}

// Without an endpoint nothing is exported, but spans are still made, so local
// records in one carry its IDs.
func TestNewWithoutEndpoint(t *testing.T) {
	p, err := New(context.Background(), Export{Version: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	NewRecorder(p.Meter).AuthFailure(context.Background(), "unknown_key", IdentityTypeUnknown)
	ctx, span := Tracer(p.Tracer).Start(context.Background(), "ssh connection")
	if !span.SpanContext().IsValid() {
		t.Error("no span without an endpoint")
	}
	var local bytes.Buffer
	slog.New(p.LogHandler(slog.NewJSONHandler(&local, nil))).InfoContext(ctx, "ssh authenticated")
	span.End()
	if !strings.Contains(local.String(), `"trace_id":"`+span.SpanContext().TraceID().String()+`"`) {
		t.Errorf("local log = %s", local.String())
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The trace IDs are added to a copy of the record, so a handler after this
// one sees the record as logged. Attributes and groups pass through.
func TestTracedHandler(t *testing.T) {
	var local bytes.Buffer
	h := traced{slog.NewJSONHandler(&local, nil)}.WithAttrs([]slog.Attr{slog.String("identity", "alice")}).WithGroup("g")
	tp := sdktrace.NewTracerProvider()
	ctx, span := tp.Tracer("test").Start(context.Background(), "s")
	defer span.End()
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "msg", 0)
	r.AddAttrs(slog.String("k", "v"))
	if err := h.Handle(ctx, r); err != nil {
		t.Fatal(err)
	}
	if r.NumAttrs() != 1 {
		t.Errorf("caller's record changed: %d attributes", r.NumAttrs())
	}
	out := local.String()
	if !strings.Contains(out, `"identity":"alice","g":{"k":"v","trace_id":"`+span.SpanContext().TraceID().String()+`"`) {
		t.Errorf("log = %s", out)
	}
}

// With HTTPOptions, a request served is a new trace whatever traceparent it
// carries, and a request sent carries no trace context, but both are spans
// from the given provider.
func TestHTTPOptions(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	var sent http.Header
	srv := httptest.NewServer(otelhttp.NewHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		sent = r.Header.Clone()
	}), "test", HTTPOptions(tp)...))
	defer srv.Close()
	client := &http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport, HTTPOptions(tp)...)}
	ctx, parent := Tracer(tp).Start(context.Background(), "provider full sync")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	parent.End()
	if sent.Get("Traceparent") != "" {
		t.Errorf("trace context sent: %v", sent)
	}
	var server, outgoing sdktrace.ReadOnlySpan
	for _, s := range sr.Ended() {
		switch s.SpanKind() {
		case trace.SpanKindServer:
			server = s
		case trace.SpanKindClient:
			outgoing = s
		}
	}
	if outgoing == nil || outgoing.Parent().SpanID() != parent.SpanContext().SpanID() {
		t.Fatalf("outgoing request span = %v", outgoing)
	}
	if server == nil || server.Parent().IsValid() || server.SpanContext().TraceID() == parent.SpanContext().TraceID() {
		t.Fatalf("served request span = %v, joined the caller's trace", server)
	}
}

// Start makes a child of the span in ctx from that span's provider, and
// nothing recordable without one; Annotate writes to the span in ctx.
func TestStart(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	ctx, parent := Tracer(tp).Start(context.Background(), "parent")
	child, span := Start(ctx, "child", attribute.String(AttrOID, "abc"))
	Annotate(child, attribute.String(AttrOutcome, "issued"))
	span.End()
	parent.End()
	ended := sr.Ended()
	if len(ended) != 2 || ended[0].Name() != "child" || ended[0].Parent().SpanID() != parent.SpanContext().SpanID() ||
		ended[0].InstrumentationScope().Name != scopeName {
		t.Fatalf("spans = %v", ended)
	}
	attrs := attribute.NewSet(ended[0].Attributes()...)
	if oid, _ := attrs.Value(AttrOID); oid.AsString() != "abc" || attrs.Len() != 2 {
		t.Errorf("attributes = %v", attrs.ToSlice())
	}
	if _, orphan := Start(context.Background(), "orphan"); orphan.IsRecording() {
		t.Error("a span with no parent records")
	}
}

// Each exporter refuses a CA certificate for a cleartext endpoint; the error
// is reported rather than exporting without the TLS the operator asked for.
func TestNewExporterErrors(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsSrv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw})
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, signal := range []string{"metrics", "traces", "logs"} {
		t.Run(signal, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_"+strings.ToUpper(signal)+"_CERTIFICATE", ca)
			_, err := New(context.Background(), Export{Endpoint: "http://127.0.0.1:1"})
			if err == nil || !strings.Contains(err.Error(), "otlp "+signal+" exporter") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// A failing collector is reported by every pipeline: metrics and logs in
// Shutdown's error, traces through the OpenTelemetry error handler, which the
// server points at its local log (ErrorHandler), as its batch span processor
// reports export failures there and not to its caller.
func TestShutdownReportsFailures(t *testing.T) {
	var handled syncBuffer
	defer otel.SetErrorHandler(otel.GetErrorHandler())
	otel.SetErrorHandler(ErrorHandler(slog.New(slog.NewJSONHandler(&handled, nil))))
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no "+r.URL.Path, http.StatusBadRequest)
	}))
	defer broken.Close()
	p, err := New(context.Background(), Export{Endpoint: broken.URL})
	if err != nil {
		t.Fatal(err)
	}
	NewRecorder(p.Meter).TokenIssued(context.Background(), "upload", "1", "alice")
	_, span := Tracer(p.Tracer).Start(context.Background(), "ssh exec")
	span.End()
	// The local handler must accept the record for it to be exported.
	var local bytes.Buffer
	slog.New(p.LogHandler(slog.NewJSONHandler(&local, nil))).Info("token issued")
	err = p.Shutdown(context.Background())
	for _, path := range []string{"/v1/metrics", "/v1/logs"} {
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("err = %v, want %s's failure", err, path)
		}
	}
	if out := handled.String(); !strings.Contains(out, "telemetry export failed") || !strings.Contains(out, "/v1/traces") {
		t.Errorf("trace export failure not reported: %s", out)
	}
}

// syncBuffer is a buffer the error handler may write to from the exporter's
// goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestErrorHandler(t *testing.T) {
	var buf bytes.Buffer
	ErrorHandler(slog.New(slog.NewJSONHandler(&buf, nil))).Handle(errors.New("collector unreachable"))
	if out := buf.String(); !strings.Contains(out, `"msg":"telemetry export failed"`) || !strings.Contains(out, "collector unreachable") {
		t.Fatalf("log = %s", out)
	}
}

// Object sizes are a histogram labelled by operation and repo, never by user.
func TestRecorderObjectSize(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	r := NewRecorder(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	r.ObjectSize(context.Background(), "upload", "1", 100)
	r.ObjectSize(context.Background(), "upload", "1", 50)
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	if len(rm.ScopeMetrics) != 1 || len(rm.ScopeMetrics[0].Metrics) != 1 {
		t.Fatalf("metrics = %+v", rm.ScopeMetrics)
	}
	m := rm.ScopeMetrics[0].Metrics[0]
	h, ok := m.Data.(metricdata.Histogram[int64])
	if m.Name != MetricObjectSize || !ok || len(h.DataPoints) != 1 {
		t.Fatalf("%s is %T", m.Name, m.Data)
	}
	dp := h.DataPoints[0]
	if dp.Count != 2 || dp.Sum != 150 || dp.Attributes.Equivalent() != set(LabelOperation, "upload", LabelRepo, "1") {
		t.Errorf("point = %+v", dp)
	}
}

func TestObserveDatastoreAge(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	age, ok := time.Duration(0), false
	ObserveDatastoreAge(mp, func() (time.Duration, bool) { return age, ok })
	gauge := func() []metricdata.DataPoint[float64] {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatal(err)
		}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if g, ok := m.Data.(metricdata.Gauge[float64]); ok && m.Name == MetricDatastoreAge {
					return g.DataPoints
				}
			}
		}
		return nil
	}
	if pts := gauge(); len(pts) != 0 {
		t.Errorf("age reported before a snapshot: %+v", pts)
	}
	age, ok = 90*time.Second, true
	if pts := gauge(); len(pts) != 1 || pts[0].Value != 90 {
		t.Errorf("age = %+v, want 90", pts)
	}
}
