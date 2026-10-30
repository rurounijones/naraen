package sshd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/rurounijones/naraen/internal/telemetry"
)

// noRec records nothing, for tests that do not look at metrics.
func noRec() *telemetry.Recorder { return telemetry.NewRecorder(noop.NewMeterProvider()) }

// syncBuffer lets a test read what the server logs while it runs.
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

// records returns every JSON log record written so far whose message is msg.
func (s *syncBuffer) records(t *testing.T, msg string) []map[string]any {
	t.Helper()
	raw := s.String()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		var r map[string]any
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("log line %q: %v", sc.Text(), err)
		}
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

// record waits for the first log record with message msg. The server logs
// after the client has its answer, so the record may arrive a little later.
func (s *syncBuffer) record(t *testing.T, msg string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if rs := s.records(t, msg); len(rs) > 0 {
			return rs[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q record in:\n%s", msg, s.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// checkFields asserts that r holds each of want's fields with that value.
func checkFields(t *testing.T, r map[string]any, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s: %s = %v, want %q (record %v)", r["msg"], k, r[k], v, r)
		}
	}
}

// counts returns metric name's data points, keyed by their attributes
// written as "k=v,k=v".
func counts(t *testing.T, r *sdkmetric.ManualReader, name string) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s is %T", name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				got[dp.Attributes.Encoded(attribute.DefaultEncoder())] = dp.Value
			}
		}
	}
	return got
}

// waitCount waits until metric name's point for attrs reaches want.
func waitCount(t *testing.T, r *sdkmetric.ManualReader, name, attrs string, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := counts(t, r, name)
		if got[attrs] == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s{%s} = %d, want %d (all points: %v)", name, attrs, got[attrs], want, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
