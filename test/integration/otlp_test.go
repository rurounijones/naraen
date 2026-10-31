//go:build integration

package integration

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// syncBuffer collects the server's output while it runs.
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

// otlpReceiver stands in for the telemetry backend: it accepts OTLP/HTTP
// protobuf pushes of metrics, traces and logs, as OpenObserve does, and keeps
// every request.
type otlpReceiver struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*collectormetrics.ExportMetricsServiceRequest
	logs     []*collectorlogs.ExportLogsServiceRequest
	traces   []*collectortrace.ExportTraceServiceRequest
}

func newOTLPReceiver(t *testing.T) *otlpReceiver {
	t.Helper()
	r := &otlpReceiver{}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		var (
			msg  proto.Message
			resp proto.Message
		)
		switch req.URL.Path {
		case "/v1/metrics":
			msg, resp = &collectormetrics.ExportMetricsServiceRequest{}, &collectormetrics.ExportMetricsServiceResponse{}
		case "/v1/logs":
			msg, resp = &collectorlogs.ExportLogsServiceRequest{}, &collectorlogs.ExportLogsServiceResponse{}
		case "/v1/traces":
			msg, resp = &collectortrace.ExportTraceServiceRequest{}, &collectortrace.ExportTraceServiceResponse{}
		}
		if err != nil || msg == nil || proto.Unmarshal(body, msg) != nil {
			http.Error(w, "bad export", http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		switch m := msg.(type) {
		case *collectormetrics.ExportMetricsServiceRequest:
			r.requests = append(r.requests, m)
		case *collectorlogs.ExportLogsServiceRequest:
			r.logs = append(r.logs, m)
		case *collectortrace.ExportTraceServiceRequest:
			r.traces = append(r.traces, m)
		}
		r.mu.Unlock()
		out, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(out)
	}))
	t.Cleanup(r.Close)
	return r
}

// records returns every log record received, each as its attributes plus
// "msg" for the body, "level" for the severity text and "trace" for the
// trace ID in hex, "" for none.
func (r *otlpReceiver) records() []map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var got []map[string]string
	for _, req := range r.logs {
		for _, rl := range req.GetResourceLogs() {
			for _, sl := range rl.GetScopeLogs() {
				for _, lr := range sl.GetLogRecords() {
					rec := map[string]string{
						"msg": lr.GetBody().GetStringValue(), "level": lr.GetSeverityText(),
						"trace": hex.EncodeToString(lr.GetTraceId()),
					}
					for _, kv := range lr.GetAttributes() {
						rec[kv.GetKey()] = kv.GetValue().GetStringValue()
					}
					got = append(got, rec)
				}
			}
		}
	}
	return got
}

// span is one received span, with IDs in hex and attribute values as text.
type span struct {
	name, trace, id, parent string
	attrs                   map[string]string
	failed                  bool
}

// spans returns every span received.
func (r *otlpReceiver) spans() []span {
	r.mu.Lock()
	defer r.mu.Unlock()
	var got []span
	for _, req := range r.traces {
		for _, rs := range req.GetResourceSpans() {
			for _, ss := range rs.GetScopeSpans() {
				for _, s := range ss.GetSpans() {
					sp := span{
						name: s.GetName(), trace: hex.EncodeToString(s.GetTraceId()), id: hex.EncodeToString(s.GetSpanId()),
						parent: hex.EncodeToString(s.GetParentSpanId()), attrs: map[string]string{},
						failed: s.GetStatus().GetCode() == tracepb.Status_STATUS_CODE_ERROR,
					}
					for _, kv := range s.GetAttributes() {
						v := kv.GetValue()
						sp.attrs[kv.GetKey()] = v.GetStringValue()
						if _, ok := v.GetValue().(*commonpb.AnyValue_IntValue); ok {
							sp.attrs[kv.GetKey()] = strconv.FormatInt(v.GetIntValue(), 10)
						}
					}
					got = append(got, sp)
				}
			}
		}
	}
	return got
}

// find returns the spans named name that hold each of want's attributes.
func find(spans []span, name string, want map[string]string) []span {
	var out []span
	for _, s := range spans {
		match := s.name == name
		for k, v := range want {
			match = match && s.attrs[k] == v
		}
		if match {
			out = append(out, s)
		}
	}
	return out
}

// counters returns the latest value of every int64 sum data point received,
// keyed as "name{k=v,k=v}" with keys sorted. Sums are cumulative, so the
// largest value seen is the final one.
func (r *otlpReceiver) counters(t *testing.T) map[string]int64 {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	got := map[string]int64{}
	for _, req := range r.requests {
		for _, rm := range req.GetResourceMetrics() {
			for _, sm := range rm.GetScopeMetrics() {
				for _, m := range sm.GetMetrics() {
					for _, dp := range m.GetSum().GetDataPoints() {
						var labels []string
						for _, kv := range dp.GetAttributes() {
							labels = append(labels, kv.GetKey()+"="+kv.GetValue().GetStringValue())
						}
						slices.Sort(labels)
						key := fmt.Sprintf("%s{%s}", m.GetName(), strings.Join(labels, ","))
						got[key] = max(got[key], dp.GetAsInt())
					}
				}
			}
		}
	}
	return got
}
