package provider

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/telemetry"
)

// scripted returns the next result on each FullSync and cancels the run
// once it has none left.
type scripted struct {
	mu      sync.Mutex
	results []func() (*datastore.Snapshot, error)
	cancel  context.CancelFunc
}

func (s *scripted) Name() string { return "scripted" }

func (s *scripted) FullSync(context.Context) (*datastore.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.results[0]
	s.results = s.results[1:]
	if len(s.results) == 0 {
		s.cancel()
	}
	return next()
}

func snapshot(t *testing.T, people int) *datastore.Snapshot {
	t.Helper()
	var d datastore.Data
	for i := range people {
		d.Identities = append(d.Identities, datastore.Identity{ID: "p" + strings.Repeat("x", i), Kind: datastore.KindPerson, Active: true})
		d.Repos = append(d.Repos, datastore.Repo{ID: "r" + strings.Repeat("x", i), Path: "acme/r" + strings.Repeat("x", i)})
	}
	s, err := datastore.NewSnapshot(d)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The first sync makes the store ready; a failed sync and one the store
// rejects leave it serving the last good snapshot.
func TestRun(t *testing.T) {
	store := datastore.NewStore(time.Hour, datastore.DefaultLimits)
	good := snapshot(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	p := &scripted{cancel: cancel, results: []func() (*datastore.Snapshot, error){
		func() (*datastore.Snapshot, error) { return good, nil },
		func() (*datastore.Snapshot, error) { return nil, errors.New("github down") },
		// Swap rejects an empty snapshot.
		func() (*datastore.Snapshot, error) { return snapshot(t, 0), nil },
	}}
	var logs bytes.Buffer
	reader := sdkmetric.NewManualReader()
	done := make(chan struct{})
	go func() {
		Run(ctx, p, store, time.Millisecond, telemetry.NewRecorder(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))), slog.New(slog.NewTextHandler(&logs, nil)))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop when its context ended")
	}
	if cur, err := store.Current(); err != nil || cur != good {
		t.Errorf("store holds %v, %v; want the first snapshot", cur, err)
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	failures := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if s, ok := m.Data.(metricdata.Sum[int64]); ok && m.Name == telemetry.MetricSyncFailures {
				for _, dp := range s.DataPoints {
					v, _ := dp.Attributes.Value(telemetry.LabelReason)
					failures[v.AsString()] = dp.Value
				}
			}
		}
	}
	if failures["failed"] != 1 || failures["rejected"] != 1 {
		t.Errorf("sync failures = %v", failures)
	}
	out := logs.String()
	applied, failed, rejected := strings.Index(out, "full sync applied"), strings.Index(out, "full sync failed"), strings.Index(out, "full sync rejected")
	if applied < 0 || failed < applied || rejected < failed || !strings.Contains(out, "provider=scripted") {
		t.Errorf("want applied, failed, rejected in that order:\n%s", out)
	}
}
