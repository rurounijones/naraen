package persist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/storage"
	"github.com/rurounijones/naraen/internal/telemetry"
	"github.com/rurounijones/naraen/internal/token"
)

const fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

var (
	k1 = token.Key{ID: "k1", Secret: bytes.Repeat([]byte{1, 2}, 16)}
	k2 = token.Key{ID: "k2", Secret: bytes.Repeat([]byte{3, 4}, 16)}
	t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
)

type bucket struct {
	mu      sync.Mutex
	objects map[string][]byte
	readErr error
	putErr  error
	puts    chan struct{}
}

func newBucket() *bucket {
	return &bucket{objects: map[string][]byte{}, puts: make(chan struct{}, 10)}
}

func (b *bucket) ReadObject(_ context.Context, key string) ([]byte, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	body, ok := b.objects[key]
	return body, ok, b.readErr
}

func (b *bucket) WriteObject(_ context.Context, key string, body []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	defer func() { b.puts <- struct{}{} }()
	if b.putErr != nil {
		return b.putErr
	}
	b.objects[key] = body
	return nil
}

func data() datastore.Data {
	return datastore.Data{
		Identities: []datastore.Identity{{ID: "alice", Kind: datastore.KindPerson, Name: "alice", Active: true}},
		Keys:       []datastore.Key{{Fingerprint: fingerprint, Type: "ssh-ed25519", IdentityID: "alice"}},
		Repos:      []datastore.Repo{{ID: "1", Path: "acme/assets"}},
		Grants:     []datastore.Grant{{IdentityID: "alice", RepoID: "1", Level: datastore.LevelWrite}},
	}
}

func snapshot(t *testing.T) *datastore.Snapshot {
	t.Helper()
	s, err := datastore.NewSnapshot(data())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newStore(now time.Time) *datastore.Store {
	st := datastore.NewStore(time.Hour, datastore.DefaultLimits)
	st.Now = func() time.Time { return now }
	return st
}

func logger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

func recorder() *telemetry.Recorder { return telemetry.NewRecorder(metricnoop.NewMeterProvider()) }

func sealed(t *testing.T, keys []token.Key, began time.Time) []byte {
	t.Helper()
	body, err := seal(keys, snapshot(t), began)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// resign signs an arbitrary payload, as an attacker holding the key could.
func resign(t *testing.T, k token.Key, payload []byte) []byte {
	t.Helper()
	body, err := json.Marshal(envelope{KeyID: k.ID, Payload: payload, MAC: mac(k, payload)})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRestore(t *testing.T) {
	b := newBucket()
	b.objects[storage.SnapshotKey] = sealed(t, []token.Key{k1}, t0)
	st := newStore(t0.Add(30 * time.Minute))
	log, logs := logger()
	Restore(context.Background(), st, b, []token.Key{k1}, log)
	snap, err := st.Current()
	if err != nil {
		t.Fatalf("not restored: %v\n%s", err, logs)
	}
	if id, ok := snap.KeyOwner(fingerprint); !ok || id.ID != "alice" {
		t.Errorf("key owner = %v, %v", id, ok)
	}
	if snap.GrantLevel("alice", "1") != datastore.LevelWrite {
		t.Errorf("grant = %v", snap.GrantLevel("alice", "1"))
	}
	// The age is the original sync's, not the restart's.
	if age, _ := st.Age(); age != 30*time.Minute {
		t.Errorf("age = %v", age)
	}
	if !strings.Contains(logs.String(), "datastore restored") {
		t.Errorf("not logged: %s", logs)
	}
}

// A copy signed with a key that has since stopped minting still verifies while
// it stays listed.
func TestRestoreAfterRotation(t *testing.T) {
	b := newBucket()
	b.objects[storage.SnapshotKey] = sealed(t, []token.Key{k1}, t0)
	st := newStore(t0)
	log, _ := logger()
	Restore(context.Background(), st, b, []token.Key{k2, k1}, log)
	if !st.Ready() {
		t.Error("copy signed with a listed key refused")
	}
}

// Every failure leaves the server not-ready rather than serving a copy it
// cannot trust, and none of them stops it.
func TestRestoreRefuses(t *testing.T) {
	good := sealed(t, []token.Key{k1}, t0)
	var e envelope
	if err := json.Unmarshal(good, &e); err != nil {
		t.Fatal(err)
	}
	flipped := bytes.Clone(e.Payload)
	flipped[len(flipped)/2] ^= 1
	tampered, err := json.Marshal(envelope{KeyID: e.KeyID, Payload: flipped, MAC: e.MAC})
	if err != nil {
		t.Fatal(err)
	}
	unknownKey, err := json.Marshal(envelope{KeyID: "k2", Payload: e.Payload, MAC: e.MAC})
	if err != nil {
		t.Fatal(err)
	}
	// Properly signed, but by a key the server does not list.
	wrongName := resign(t, k2, e.Payload)
	invalid, err := json.Marshal(saved{Began: t0, Data: datastore.Data{Identities: []datastore.Identity{{}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body []byte
		keys []token.Key
		err  error
		now  time.Time
		log  string
	}{
		{name: "missing", log: "no saved datastore snapshot"},
		{name: "read error", body: good, err: errors.New("denied"), log: "could not be read"},
		{name: "not json", body: []byte("{"), log: "refused"},
		{name: "tampered", body: tampered, log: "does not verify"},
		{name: "unknown key", body: unknownKey, log: "does not verify"},
		{name: "signed by a key no longer listed", body: wrongName, log: "does not verify"},
		{name: "signed nonsense", body: resign(t, k1, []byte("[")), log: "refused"},
		{name: "signed invalid data", body: resign(t, k1, invalid), log: "refused"},
		{name: "too old", body: good, now: t0.Add(time.Hour + time.Second), log: "too old"},
		{name: "from the future", body: good, now: t0.Add(-time.Second), log: "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBucket()
			b.readErr = tc.err
			if tc.body != nil {
				b.objects[storage.SnapshotKey] = tc.body
			}
			now := tc.now
			if now.IsZero() {
				now = t0
			}
			st := newStore(now)
			log, logs := logger()
			Restore(context.Background(), st, b, []token.Key{k1}, log)
			if st.Ready() {
				t.Error("server became ready")
			}
			if !strings.Contains(logs.String(), tc.log) {
				t.Errorf("log %q missing from: %s", tc.log, logs)
			}
		})
	}
}

// Restore gives up on a bucket that does not answer, instead of holding up
// startup.
func TestRestoreBoundsItsWait(t *testing.T) {
	var deadline time.Time
	objects := readFunc(func(ctx context.Context) {
		deadline, _ = ctx.Deadline()
	})
	log, _ := logger()
	Restore(context.Background(), newStore(t0), objects, []token.Key{k1}, log)
	if left := time.Until(deadline); left <= 0 || left > restoreTimeout {
		t.Errorf("time left = %v", left)
	}
}

type readFunc func(context.Context)

func (f readFunc) ReadObject(ctx context.Context, _ string) ([]byte, bool, error) {
	f(ctx)
	return nil, false, nil
}

func (f readFunc) WriteObject(context.Context, string, []byte) error { return nil }

func waitPut(t *testing.T, b *bucket) {
	t.Helper()
	select {
	case <-b.puts:
	case <-time.After(5 * time.Second):
		t.Fatal("no write")
	}
}

// Both a full sync and a narrowing reach the bucket: without the second, a
// restart would hand back access a webhook removed.
func TestRunSavesEveryChange(t *testing.T) {
	b := newBucket()
	st := newStore(t0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	log, _ := logger()
	go func() {
		Run(ctx, st, b, []token.Key{k1}, tracenoop.NewTracerProvider(), recorder(), log)
		close(done)
	}()
	if err := st.Swap(st.StartSync(), snapshot(t)); err != nil {
		t.Fatal(err)
	}
	waitPut(t, b)
	st.Narrow(datastore.Narrowing{RevokeKeys: []string{fingerprint}})
	waitPut(t, b)
	cancel()
	<-done

	next := newStore(t0)
	Restore(context.Background(), next, b, []token.Key{k1}, log)
	snap, err := next.Current()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap.KeyOwner(fingerprint); ok {
		t.Error("revoked key came back after a restart")
	}
}

func TestSaveNothingPublished(t *testing.T) {
	b := newBucket()
	log, _ := logger()
	save(context.Background(), tracenoop.NewTracerProvider().Tracer(""), newStore(t0), b, []token.Key{k1}, recorder(), log)
	if len(b.objects) != 0 {
		t.Errorf("wrote %v", b.objects)
	}
}

// A failed save is counted, logged and marked on its span, and does not stop
// later ones.
func TestSaveFailure(t *testing.T) {
	b := newBucket()
	b.putErr = errors.New("denied")
	st := newStore(t0)
	if err := st.Swap(st.StartSync(), snapshot(t)); err != nil {
		t.Fatal(err)
	}
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	reader := sdkmetric.NewManualReader()
	rec := telemetry.NewRecorder(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	log, logs := logger()
	save(context.Background(), tp.Tracer(""), st, b, []token.Key{k1}, rec, log)
	if !strings.Contains(logs.String(), "not saved") {
		t.Errorf("not logged: %s", logs)
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var count int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if s, ok := m.Data.(metricdata.Sum[int64]); ok && m.Name == telemetry.MetricSnapshotSaveFailures {
				count = s.DataPoints[0].Value
			}
		}
	}
	if count != 1 {
		t.Errorf("failures = %d", count)
	}
	spans := sr.Ended()
	if len(spans) != 1 || spans[0].Name() != "datastore snapshot save" || spans[0].Status().Code != codes.Error {
		t.Errorf("spans = %v", spans)
	}

	b.mu.Lock()
	b.putErr = nil
	b.mu.Unlock()
	<-b.puts
	logs.Reset()
	save(context.Background(), tp.Tracer(""), st, b, []token.Key{k1}, rec, log)
	if !strings.Contains(logs.String(), "snapshot saved") || len(b.objects) != 1 {
		t.Errorf("retry: %s", logs)
	}
	if got := sr.Ended()[1].Status().Code; got == codes.Error {
		t.Error("successful save marked failed")
	}
}

// A time JSON cannot encode fails the save without reaching the bucket.
func TestSaveUnencodable(t *testing.T) {
	b := newBucket()
	st := newStore(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := st.Swap(st.StartSync(), snapshot(t)); err != nil {
		t.Fatal(err)
	}
	log, logs := logger()
	save(context.Background(), tracenoop.NewTracerProvider().Tracer(""), st, b, []token.Key{k1}, recorder(), log)
	if !strings.Contains(logs.String(), "not saved") || len(b.objects) != 0 {
		t.Errorf("wrote %v: %s", b.objects, logs)
	}
}

// The MAC is specific to this use, so a saved copy can never pass as a token
// signed with the same key, or the other way round.
func TestMACDomain(t *testing.T) {
	if bytes.Equal(mac(k1, []byte("p")), mac(token.Key{ID: "k1", Secret: k2.Secret}, []byte("p"))) {
		t.Error("secret not covered")
	}
	if bytes.Equal(mac(k1, []byte("p")), mac(token.Key{ID: "k3", Secret: k1.Secret}, []byte("p"))) {
		t.Error("key ID not covered")
	}
	if bytes.Equal(mac(k1, []byte("p")), mac(k1, []byte("q"))) {
		t.Error("payload not covered")
	}
}
