//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
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
// protobuf pushes of metrics and logs, as OpenObserve does, and keeps every
// request.
type otlpReceiver struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*collectormetrics.ExportMetricsServiceRequest
	logs     []*collectorlogs.ExportLogsServiceRequest
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
// "msg" for the body and "level" for the severity text.
func (r *otlpReceiver) records() []map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var got []map[string]string
	for _, req := range r.logs {
		for _, rl := range req.GetResourceLogs() {
			for _, sl := range rl.GetScopeLogs() {
				for _, lr := range sl.GetLogRecords() {
					rec := map[string]string{"msg": lr.GetBody().GetStringValue(), "level": lr.GetSeverityText()}
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
