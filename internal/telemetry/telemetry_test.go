package telemetry

import (
	"bytes"
	"context"
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

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"
)

// collect returns every counter data point the reader holds, keyed by metric
// name and then by the point's attributes.
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
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || !sum.IsMonotonic {
				t.Fatalf("%s is %T, want a monotonic int64 sum", m.Name, m.Data)
			}
			got[m.Name] = map[attribute.Distinct]int64{}
			for _, dp := range sum.DataPoints {
				got[m.Name][dp.Attributes.Equivalent()] = dp.Value
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

	got := collect(t, reader)
	want := map[string]map[attribute.Distinct]int64{
		MetricAuthFailures: {
			set(LabelReason, "unknown_key", LabelIdentityType, "unknown"):       2,
			set(LabelReason, "insufficient_grant", LabelIdentityType, "person"): 1,
		},
		MetricTokensIssued:     {set(LabelOperation, "upload", LabelRepo, "1", LabelUser, "alice"): 1},
		MetricSSHConnsRejected: {set(LabelReason, "rate"): 1},
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
				}
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

// Metrics and logs go to their paths under the configured base URL with the
// configured headers, and Shutdown flushes what was recorded since the last
// push. Logs reach the local handler too, and the backend receives exactly
// the records the local handler accepts.
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
	var local bytes.Buffer
	log := slog.New(p.LogHandler(slog.NewJSONHandler(&local, nil))).With("identity", "alice").WithGroup("g")
	log.Debug("below the local level")
	log.Info("token issued", "repo", "acme/assets")
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()
	for _, path := range []string{"/api/default/v1/metrics", "/api/default/v1/logs"} {
		if h, ok := rc.headers[path]; !ok || h.Get("Authorization") != "Basic c2VjcmV0" {
			t.Errorf("%s: pushed %v with headers %v", path, ok, h)
		}
	}
	if want := []string{"INFO token issued identity=alice g.repo=acme/assets"}; !slices.Equal(rc.logs, want) {
		t.Errorf("exported logs = %q, want %q", rc.logs, want)
	}
	if out := local.String(); strings.Count(out, "\n") != 1 || !strings.Contains(out, `"msg":"token issued"`) {
		t.Errorf("local log = %s", out)
	}
}

// Without an endpoint nothing is exported and the local handler is used as is.
func TestNewWithoutEndpoint(t *testing.T) {
	p, err := New(context.Background(), Export{Version: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	NewRecorder(p.Meter).AuthFailure(context.Background(), "unknown_key", IdentityTypeUnknown)
	local := slog.DiscardHandler
	if h := p.LogHandler(local); h != local {
		t.Errorf("LogHandler wrapped the local handler: %T", h)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
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
	for _, signal := range []string{"metrics", "logs"} {
		t.Run(signal, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_"+strings.ToUpper(signal)+"_CERTIFICATE", ca)
			_, err := New(context.Background(), Export{Endpoint: "http://127.0.0.1:1"})
			if err == nil || !strings.Contains(err.Error(), "otlp "+signal+" exporter") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// A failing collector is reported by both pipelines.
func TestShutdownReportsFailures(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusBadRequest)
	}))
	defer broken.Close()
	p, err := New(context.Background(), Export{Endpoint: broken.URL})
	if err != nil {
		t.Fatal(err)
	}
	NewRecorder(p.Meter).TokenIssued(context.Background(), "upload", "1", "alice")
	// The local handler must accept the record for it to be exported.
	var local bytes.Buffer
	slog.New(p.LogHandler(slog.NewJSONHandler(&local, nil))).Info("token issued")
	err = p.Shutdown(context.Background())
	if err == nil || !strings.Contains(err.Error(), "metrics") || !strings.Contains(err.Error(), "logs") {
		t.Fatalf("err = %v", err)
	}
}

func TestErrorHandler(t *testing.T) {
	var buf bytes.Buffer
	ErrorHandler(slog.New(slog.NewJSONHandler(&buf, nil))).Handle(errors.New("collector unreachable"))
	if out := buf.String(); !strings.Contains(out, `"msg":"telemetry export failed"`) || !strings.Contains(out, "collector unreachable") {
		t.Fatalf("log = %s", out)
	}
}
