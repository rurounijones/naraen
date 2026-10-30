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

	"github.com/rurounijones/naraen/internal/datastore"
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
	done := make(chan struct{})
	go func() {
		Run(ctx, p, store, time.Millisecond, slog.New(slog.NewTextHandler(&logs, nil)))
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
	for _, want := range []string{"full sync applied", "full sync failed", "full sync rejected", "provider=scripted"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs.String())
		}
	}
}
