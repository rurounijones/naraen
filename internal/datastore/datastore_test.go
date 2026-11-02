package datastore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// fp returns a well-formed fingerprint derived from name.
func fp(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

const jwks = `{"keys":[]}`

func sample(t *testing.T) Data {
	t.Helper()
	return Data{
		Meta: Meta{Provider: "test", Version: "1", SyncedAt: t0},
		Identities: []Identity{
			{ID: "alice", Kind: KindPerson, Name: "Alice", Active: true},
			{ID: "bob", Kind: KindPerson, Name: "Bob", Active: false},
		},
		Keys: []Key{
			{Fingerprint: fp("alice"), Type: "ssh-ed25519", IdentityID: "alice"},
			{Fingerprint: fp("bob"), Type: "ssh-ed25519", IdentityID: "bob"},
		},
		Repos:  []Repo{{ID: "r1", Path: "acme/assets", Aliases: []string{"acme/old-name"}}},
		Grants: []Grant{{IdentityID: "alice", RepoID: "r1", Level: LevelWrite}},
		Trusts: []WorkloadTrust{{Issuer: "https://issuer", Audience: "aud", JWKS: jwks, RepoClaim: "repository_id", MaxLevel: LevelRead}},
	}
}

func TestLevelText(t *testing.T) {
	for l := LevelNone; l <= LevelAdmin; l++ {
		b, err := l.MarshalText()
		if err != nil || string(b) != l.String() {
			t.Fatalf("MarshalText(%d) = %q, %v", l, b, err)
		}
		var back Level
		if err := back.UnmarshalText(b); err != nil || back != l {
			t.Fatalf("UnmarshalText(%q) = %v, %v", b, back, err)
		}
	}
	if got := LevelWrite.String(); got != "write" {
		t.Errorf("LevelWrite = %q", got)
	}
	for _, bad := range []Level{LevelNone - 1, LevelAdmin + 1} {
		if _, err := bad.MarshalText(); err == nil {
			t.Errorf("MarshalText(%d) accepted", bad)
		}
		if got := bad.String(); got != fmt.Sprintf("Level(%d)", int(bad)) {
			t.Errorf("String(%d) = %q", bad, got)
		}
	}
	var l Level
	for _, bad := range []string{"2", "Write", "owner", ""} {
		if err := l.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("UnmarshalText(%q) accepted", bad)
		}
	}
}

func TestSnapshotLookups(t *testing.T) {
	s, err := NewSnapshot(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := s.KeyOwner(fp("alice")); !ok || id.ID != "alice" {
		t.Errorf("KeyOwner(alice) = %v, %v", id, ok)
	}
	if _, ok := s.KeyOwner(fp("bob")); ok {
		t.Error("inactive identity must not own a key")
	}
	if _, ok := s.KeyOwner(fp("unknown")); ok {
		t.Error("unknown key must be absent")
	}
	if holder, ok := s.KeyHolder(fp("bob")); !ok || holder != "bob" {
		t.Errorf("KeyHolder(bob) = %q, %v", holder, ok)
	}
	if holder, ok := s.KeyHolder(fp("unknown")); ok || holder != "" {
		t.Errorf("KeyHolder(unknown) = %q, %v", holder, ok)
	}
	if !s.Deactivated("bob") || s.Deactivated("alice") || s.Deactivated("ghost") {
		t.Error("Deactivated must hold only for an existing inactive identity")
	}
	if _, ok := s.Identity("bob"); ok {
		t.Error("inactive identity must be absent")
	}
	if _, ok := s.Identity("alice"); !ok {
		t.Error("alice must be present")
	}
	for _, p := range []string{"acme/assets", "acme/old-name"} {
		if r, ok := s.RepoByPath(p); !ok || r.ID != "r1" {
			t.Errorf("RepoByPath(%q) = %v, %v", p, r, ok)
		}
	}
	if _, ok := s.RepoByPath("acme/other"); ok {
		t.Error("unknown path must be absent")
	}
	if _, ok := s.Repo("r1"); !ok {
		t.Error("Repo(r1) must exist")
	}
	if _, ok := s.Repo("nope"); ok {
		t.Error("Repo(nope) must not exist")
	}
	if got := s.GrantLevel("alice", "r1"); got != LevelWrite {
		t.Errorf("GrantLevel = %v", got)
	}
	if got := s.GrantLevel("alice", "r2"); got != LevelNone {
		t.Errorf("missing grant = %v, want none", got)
	}
	if got := s.Meta().Provider; got != "test" {
		t.Errorf("Meta().Provider = %q", got)
	}
	trusts := s.Trusts()
	if len(trusts) != 1 {
		t.Fatalf("Trusts() = %v", trusts)
	}
	trusts[0].Issuer = "mutated"
	if s.Trusts()[0].Issuer == "mutated" {
		t.Error("Trusts must return a copy")
	}
}

func TestNewSnapshotRejects(t *testing.T) {
	tests := map[string]func(*Data){
		"repo id with a slash":  func(d *Data) { d.Repos[0].ID = "a/b" },
		"empty identity id":     func(d *Data) { d.Identities[0].ID = "" },
		"unknown kind":          func(d *Data) { d.Identities[0].Kind = "robot" },
		"empty kind":            func(d *Data) { d.Identities[0].Kind = "" },
		"duplicate identity":    func(d *Data) { d.Identities = append(d.Identities, d.Identities[0]) },
		"empty fingerprint":     func(d *Data) { d.Keys[0].Fingerprint = "" },
		"fingerprint no prefix": func(d *Data) { d.Keys[0].Fingerprint = strings.TrimPrefix(fp("x"), "SHA256:") },
		"fingerprint md5 style": func(d *Data) { d.Keys[0].Fingerprint = "MD5:aa:bb" },
		"fingerprint short": func(d *Data) {
			d.Keys[0].Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString([]byte("short"))
		},
		"fingerprint padded":      func(d *Data) { d.Keys[0].Fingerprint = fp("x") + "=" },
		"key unknown identity":    func(d *Data) { d.Keys[0].IdentityID = "ghost" },
		"duplicate fingerprint":   func(d *Data) { d.Keys[1].Fingerprint = d.Keys[0].Fingerprint },
		"empty repo path":         func(d *Data) { d.Repos[0].Path = "" },
		"empty repo id":           func(d *Data) { d.Repos[0].ID = "" },
		"non-canonical path":      func(d *Data) { d.Repos[0].Path = "Acme/Assets" },
		"path with .git":          func(d *Data) { d.Repos[0].Path = "acme/assets.git" },
		"non-canonical alias":     func(d *Data) { d.Repos[0].Aliases = []string{"/acme/old"} },
		"duplicate repo":          func(d *Data) { d.Repos = append(d.Repos, Repo{ID: "r1", Path: "acme/x"}) },
		"path claimed twice":      func(d *Data) { d.Repos = append(d.Repos, Repo{ID: "r2", Path: "acme/old-name"}) },
		"grant unknown ident":     func(d *Data) { d.Grants[0].IdentityID = "ghost" },
		"grant unknown repo":      func(d *Data) { d.Grants[0].RepoID = "ghost" },
		"grant level none":        func(d *Data) { d.Grants[0].Level = LevelNone },
		"grant level above admin": func(d *Data) { d.Grants[0].Level = LevelAdmin + 1 },
		"duplicate grant":         func(d *Data) { d.Grants = append(d.Grants, d.Grants[0]) },
		"trust no issuer":         func(d *Data) { d.Trusts[0].Issuer = "" },
		"trust no audience":       func(d *Data) { d.Trusts[0].Audience = "" },
		"trust no repo claim":     func(d *Data) { d.Trusts[0].RepoClaim = "" },
		"trust no jwks":           func(d *Data) { d.Trusts[0].JWKS = "" },
		"trust bad jwks":          func(d *Data) { d.Trusts[0].JWKS = "{" },
		"trust write":             func(d *Data) { d.Trusts[0].MaxLevel = LevelWrite },
		"trust none":              func(d *Data) { d.Trusts[0].MaxLevel = LevelNone },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			d := sample(t)
			mutate(&d)
			if _, err := NewSnapshot(d); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	for _, kind := range []IdentityKind{KindDeployKey, KindWorkload} {
		d := sample(t)
		d.Identities[0].Kind = kind
		if _, err := NewSnapshot(d); err != nil {
			t.Errorf("kind %q rejected: %v", kind, err)
		}
	}
	d := sample(t)
	d.Grants[0].Level = LevelAdmin
	if _, err := NewSnapshot(d); err != nil {
		t.Errorf("admin grant rejected: %v", err)
	}
}

// world describes a snapshot by identities (all active unless listed in
// inactive) and grants on a single repo.
type world struct {
	identities []string
	inactive   []string
	grants     map[string]Level
}

func build(t *testing.T, w world) *Snapshot {
	t.Helper()
	d := Data{Repos: []Repo{{ID: "r", Path: "a/b"}}}
	for _, id := range w.identities {
		d.Identities = append(d.Identities, Identity{ID: id, Kind: KindPerson, Active: true})
	}
	for _, id := range w.inactive {
		d.Identities = append(d.Identities, Identity{ID: id, Kind: KindPerson})
	}
	for id, l := range w.grants {
		d.Grants = append(d.Grants, Grant{IdentityID: id, RepoID: "r", Level: l})
	}
	s, err := NewSnapshot(d)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// people returns n identity names with a prefix.
func people(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return out
}

func plus(a, b []string) []string { return append(append([]string{}, a...), b...) }

func readers(ids []string) map[string]Level {
	g := make(map[string]Level, len(ids))
	for _, id := range ids {
		g[id] = LevelRead
	}
	return g
}

func ten(t *testing.T) *Snapshot {
	t.Helper()
	ids := people("p", 10)
	return build(t, world{identities: ids, grants: readers(ids)})
}

// current returns the live snapshot, failing the test if there is none.
func current(t *testing.T, st *Store) *Snapshot {
	t.Helper()
	s, err := st.Current()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newStore(maxAge time.Duration, now *time.Time) *Store {
	st := NewStore(maxAge, Limits{Slack: 1, MaxShrink: 0.5, MaxGrow: 0.5, MaxRaise: 0})
	st.Now = func() time.Time { return *now }
	return st
}

func TestStoreReadinessAndStaleness(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)

	if _, err := st.Current(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("before first sync: %v", err)
	}
	if st.Ready() {
		t.Fatal("must not be ready before first sync")
	}
	start := st.StartSync()
	now = t0.Add(10 * time.Minute) // the sync takes ten minutes
	if err := st.Swap(start, ten(t)); err != nil {
		t.Fatal(err)
	}
	if !st.Ready() {
		t.Fatal("must be ready after first sync")
	}
	// Age counts from when the sync started reading, not when it finished.
	now = t0.Add(time.Hour)
	if _, err := st.Current(); err != nil {
		t.Fatalf("at max age: %v", err)
	}
	now = t0.Add(time.Hour + time.Nanosecond)
	if _, err := st.Current(); !errors.Is(err, ErrStale) {
		t.Fatalf("past max age: %v", err)
	}
}

// A snapshot claiming to come from the future must not extend its own life.
func TestStoreIgnoresSyncedAtInData(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)
	d := sample(t)
	d.Meta.SyncedAt = t0.AddDate(10, 0, 0)
	s, err := NewSnapshot(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Swap(st.StartSync(), s); err != nil {
		t.Fatal(err)
	}
	now = t0.Add(2 * time.Hour)
	if _, err := st.Current(); !errors.Is(err, ErrStale) {
		t.Fatalf("future SyncedAt kept the snapshot fresh: %v", err)
	}
}

func TestStoreSwapLimits(t *testing.T) {
	base := people("p", 10)
	raise := func(n int) map[string]Level {
		g := readers(base)
		for _, id := range base[:n] {
			g[id] = LevelAdmin
		}
		return g
	}
	// Limits: Slack 1, shrink 50%, grow 50%, raise 0%, against 10 identities
	// and 10 grants, so up to 6 removals or additions and 1 raise.
	tests := []struct {
		name    string
		next    world
		wantErr bool
	}{
		{"unchanged", world{identities: base, grants: readers(base)}, false},
		{"six removed", world{identities: base[:4], grants: readers(base[:4])}, false},
		{"seven removed", world{identities: base[:3], grants: readers(base[:3])}, true},
		{"seven deactivated", world{identities: base[:3], inactive: base[3:], grants: readers(base[:4])}, true},
		{"seven grants removed", world{identities: base, grants: readers(base[:3])}, true},
		{"six added", world{identities: plus(base, people("n", 6)), grants: readers(base)}, false},
		{"seven identities added", world{identities: plus(base, people("n", 7)), grants: readers(base)}, true},
		{"seven grants added", world{identities: plus(base, people("n", 6)), inactive: []string{"n6"}, grants: readers(plus(base, people("n", 7)))}, true},
		{"one raised", world{identities: base, grants: raise(1)}, false},
		{"two raised", world{identities: base, grants: raise(2)}, true},
		{"all swapped for others", world{identities: people("q", 10), grants: readers(people("q", 10))}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := t0
			st := newStore(time.Hour, &now)
			if err := st.Swap(st.StartSync(), ten(t)); err != nil {
				t.Fatal(err)
			}
			before, _ := st.Current()
			next := build(t, tt.next)
			err := st.Swap(st.StartSync(), next)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrSwapRejected) {
				t.Fatalf("err = %v, want ErrSwapRejected", err)
			}
			if cur, _ := st.Current(); tt.wantErr && cur != before {
				t.Fatal("rejected snapshot was published")
			}
		})
	}
}

func TestDiffCountsOnlyAccessChanges(t *testing.T) {
	old := build(t, world{
		identities: []string{"stay", "leave", "deact"},
		inactive:   []string{"was-off", "still-off"},
		grants:     map[string]Level{"stay": LevelWrite, "leave": LevelRead, "deact": LevelAdmin},
	})
	next := build(t, world{
		identities: []string{"stay", "was-off", "new"},
		inactive:   []string{"deact", "still-off"},
		grants:     map[string]Level{"stay": LevelRead, "deact": LevelAdmin, "new": LevelRead},
	})
	got := diff(old, next)
	want := change{identitiesRemoved: 2, identitiesAdded: 2, grantsRemoved: 1, grantsAdded: 1}
	if got != want {
		t.Fatalf("diff = %+v, want %+v", got, want)
	}
	raised := build(t, world{identities: []string{"stay", "leave", "deact"}, grants: map[string]Level{"stay": LevelAdmin, "leave": LevelRead, "deact": LevelAdmin}})
	if got := diff(old, raised); got.grantsRaised != 1 {
		t.Fatalf("raised = %+v", got)
	}
}

func TestStoreSwapRejectsEmptyAndNil(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)
	if err := st.Swap(st.StartSync(), nil); !errors.Is(err, ErrSwapRejected) {
		t.Fatalf("nil swap: %v", err)
	}
	noRepos, err := NewSnapshot(Data{Identities: []Identity{{ID: "a", Kind: KindPerson, Active: true}}})
	if err != nil {
		t.Fatal(err)
	}
	noIdentities, err := NewSnapshot(Data{Repos: []Repo{{ID: "r", Path: "a/b"}}})
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]*Snapshot{"no repos": noRepos, "no identities": noIdentities} {
		if err := st.Swap(st.StartSync(), s); !errors.Is(err, ErrSwapRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if st.Ready() {
		t.Fatal("an empty first snapshot was published")
	}
}

func TestStoreRejectsSupersededSync(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)
	early := st.StartSync()
	now = t0.Add(time.Minute)
	late := st.StartSync()
	if err := st.Swap(late, ten(t)); err != nil {
		t.Fatal(err)
	}
	if err := st.Swap(early, ten(t)); !errors.Is(err, ErrSwapRejected) {
		t.Fatalf("older sync replaced a newer one: %v", err)
	}

	// Same clock reading, but a narrowing came between the two starts.
	same := st.StartSync()
	st.Narrow(Narrowing{})
	after := st.StartSync()
	if err := st.Swap(after, ten(t)); err != nil {
		t.Fatal(err)
	}
	if err := st.Swap(same, ten(t)); !errors.Is(err, ErrSwapRejected) {
		t.Fatalf("sync that missed a narrowing replaced a newer one: %v", err)
	}
}

func TestStoreApproveNextSwap(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)
	if err := st.Swap(st.StartSync(), ten(t)); err != nil {
		t.Fatal(err)
	}
	other := build(t, world{identities: people("q", 10), grants: readers(people("q", 10))})
	if err := st.Swap(st.StartSync(), other); !errors.Is(err, ErrSwapRejected) {
		t.Fatalf("large change accepted without approval: %v", err)
	}
	st.ApproveNextSwap()
	if err := st.Swap(st.StartSync(), other); err != nil {
		t.Fatalf("approved swap: %v", err)
	}
	// Approval is spent by one swap.
	if err := st.Swap(st.StartSync(), ten(t)); !errors.Is(err, ErrSwapRejected) {
		t.Fatalf("approval was reused: %v", err)
	}
}

func TestStoreNarrowAppliesAtOnce(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)
	s, err := NewSnapshot(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Swap(st.StartSync(), s); err != nil {
		t.Fatal(err)
	}
	st.Narrow(Narrowing{RevokeKeys: []string{fp("alice"), fp("nobody")}})
	cur := current(t, st)
	if _, ok := cur.KeyOwner(fp("alice")); ok {
		t.Error("revoked key still resolves")
	}
	if _, ok := s.KeyOwner(fp("alice")); !ok {
		t.Error("narrowing mutated the original snapshot")
	}
	st.Narrow(Narrowing{DeactivateIdentities: []string{"alice", "ghost"}})
	cur = current(t, st)
	if _, ok := cur.Identity("alice"); ok {
		t.Error("deactivated identity still active")
	}
	st.Narrow(Narrowing{DropGrants: []GrantRef{{IdentityID: "alice", RepoID: "r1"}}})
	cur = current(t, st)
	if cur.GrantLevel("alice", "r1") != LevelNone {
		t.Error("dropped grant still present")
	}
}

// A full sync that read its source before a revocation arrived must not
// restore the revoked access when it is swapped in.
func TestStoreReplaysNarrowingsOntoInFlightSync(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)
	stale := func() *Snapshot {
		s, err := NewSnapshot(sample(t))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// Recorded before the store is ready: still applies to the first swap.
	first := st.StartSync()
	st.Narrow(Narrowing{DropGrants: []GrantRef{{IdentityID: "alice", RepoID: "r1"}}})
	if err := st.Swap(first, stale()); err != nil {
		t.Fatal(err)
	}
	cur := current(t, st)
	if cur.GrantLevel("alice", "r1") != LevelNone {
		t.Fatal("narrowing recorded before the first sync was lost")
	}

	start := st.StartSync()
	st.Narrow(Narrowing{RevokeKeys: []string{fp("alice")}})
	if err := st.Swap(start, stale()); err != nil {
		t.Fatal(err)
	}
	cur = current(t, st)
	if _, ok := cur.KeyOwner(fp("alice")); ok {
		t.Fatal("in-flight sync restored a revoked key")
	}

	// A sync that started after the revocation has seen it; the source is
	// now authoritative again.
	if err := st.Swap(st.StartSync(), stale()); err != nil {
		t.Fatal(err)
	}
	cur = current(t, st)
	if _, ok := cur.KeyOwner(fp("alice")); !ok {
		t.Fatal("narrowing was replayed onto a sync that already saw it")
	}
	if len(st.pending) != 0 {
		t.Fatalf("pending narrowings not pruned: %d", len(st.pending))
	}
}

// Two syncs in flight over the same revocation: publishing the first must not
// discard the revocation the second has not seen.
func TestStoreKeepsNarrowingsForOtherInFlightSyncs(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)
	stale := func() *Snapshot {
		s, err := NewSnapshot(sample(t))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	a, b := st.StartSync(), st.StartSync()
	st.Narrow(Narrowing{RevokeKeys: []string{fp("alice")}})
	if err := st.Swap(a, stale()); err != nil {
		t.Fatal(err)
	}
	if err := st.Swap(b, stale()); err != nil {
		t.Fatal(err)
	}
	if _, ok := current(t, st).KeyOwner(fp("alice")); ok {
		t.Fatal("second in-flight sync restored a revoked key")
	}
}

func TestStoreConcurrentWritesAndReads(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)
	st.limits = Limits{Slack: 100}
	if err := st.Swap(st.StartSync(), ten(t)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				if _, err := st.Current(); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Go(func() {
		for i := range 50 {
			st.Narrow(Narrowing{DeactivateIdentities: []string{fmt.Sprintf("p%d", i%10)}})
		}
	})
	for range 50 {
		if err := st.Swap(st.StartSync(), ten(t)); err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
}

func TestParseSnapshot(t *testing.T) {
	good := `{"meta":{"provider":"file","synced_at":"2026-10-29T12:00:00Z"},
		"identities":[{"id":"a","kind":"person","name":"A","active":true}],
		"keys":[{"fingerprint":"` + fp("a") + `","type":"ssh-ed25519","identity_id":"a"}],
		"repos":[{"id":"r","path":"acme/assets"}],
		"grants":[{"identity_id":"a","repo_id":"r","level":"write"}]}`
	s, err := ParseSnapshot(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	if s.GrantLevel("a", "r") != LevelWrite {
		t.Error("grant not loaded")
	}
	for name, in := range map[string]string{
		"empty":         ``,
		"unknown":       `{"bogus":1}`,
		"trailing":      good + ` {}`,
		"bad ref":       `{"grants":[{"identity_id":"x","repo_id":"y","level":"read"}]}`,
		"numeric level": strings.Replace(good, `"write"`, `2`, 1),
		"unknown level": strings.Replace(good, `"write"`, `"owner"`, 1),
		"not an object": `[]`,
	} {
		if _, err := ParseSnapshot(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestGrantJSONUsesNames(t *testing.T) {
	b, err := json.Marshal(Grant{IdentityID: "a", RepoID: "r", Level: LevelMaintain})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"level":"maintain"`) {
		t.Fatalf("grant JSON = %s", b)
	}
}

func FuzzParseSnapshot(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"identities":[{"id":"a","kind":"person","active":true}]}`)
	f.Fuzz(func(t *testing.T, in string) {
		s, err := ParseSnapshot(strings.NewReader(in))
		if err == nil && s == nil {
			t.Fatal("nil snapshot without error")
		}
	})
}

func TestAge(t *testing.T) {
	st := NewStore(time.Hour, DefaultLimits)
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	st.Now = func() time.Time { return now }
	if age, ok := st.Age(); ok || age != 0 {
		t.Errorf("before the first swap: %v, %v", age, ok)
	}
	start := st.StartSync()
	snap, err := NewSnapshot(Data{
		Identities: []Identity{{ID: "a", Kind: KindPerson, Active: true}},
		Repos:      []Repo{{ID: "1", Path: "acme/x"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := st.Swap(start, snap); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Minute)
	// Age counts from when the sync began, not when it was swapped in.
	if age, ok := st.Age(); !ok || age != 11*time.Minute {
		t.Errorf("age = %v, %v; want 11m", age, ok)
	}
}

func TestSnapshotDataRoundTrip(t *testing.T) {
	s, err := NewSnapshot(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	back, err := NewSnapshot(s.Data())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.identities, back.identities) || !reflect.DeepEqual(s.keys, back.keys) ||
		!reflect.DeepEqual(s.repos, back.repos) || !reflect.DeepEqual(s.repoByPath, back.repoByPath) ||
		!reflect.DeepEqual(s.grants, back.grants) || !reflect.DeepEqual(s.trusts, back.trusts) || s.meta != back.meta {
		t.Errorf("round trip changed the snapshot: %+v != %+v", back, s)
	}
}

func TestStoreRestore(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)
	if _, _, ok := st.Latest(); ok {
		t.Fatal("Latest before any snapshot")
	}
	began := t0.Add(-30 * time.Minute)
	if err := st.Restore(ten(t), began); err != nil {
		t.Fatal(err)
	}
	if !st.Ready() {
		t.Fatal("not ready")
	}
	if snap, at, ok := st.Latest(); !ok || snap == nil || !at.Equal(began) {
		t.Errorf("Latest = %v, %v, %v", snap, at, ok)
	}
	select {
	case <-st.Changed():
		t.Error("restoring signalled a change: the copy is already saved")
	default:
	}
	// It goes stale when its sync would have, not an hour from the restart.
	now = began.Add(time.Hour)
	if !st.Ready() {
		t.Error("stale at exactly the limit")
	}
	now = began.Add(time.Hour + time.Nanosecond)
	if _, err := st.Current(); !errors.Is(err, ErrStale) {
		t.Errorf("err = %v", err)
	}
	if err := st.Restore(ten(t), now); !errors.Is(err, ErrSwapRejected) {
		t.Errorf("restored over a live snapshot: %v", err)
	}
}

func TestStoreRestoreRefuses(t *testing.T) {
	now := t0
	for name, tc := range map[string]struct {
		snap  *Snapshot
		began time.Time
		want  error
	}{
		"nil":    {nil, t0, ErrSwapRejected},
		"empty":  {build(t, world{}), t0, ErrSwapRejected},
		"future": {ten(t), t0.Add(time.Nanosecond), ErrSwapRejected},
		"stale":  {ten(t), t0.Add(-time.Hour - time.Nanosecond), ErrStale},
	} {
		st := newStore(time.Hour, &now)
		if err := st.Restore(tc.snap, tc.began); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v", name, err)
		}
		if st.Ready() {
			t.Errorf("%s: became ready", name)
		}
	}
	// A snapshot exactly at either bound is accepted.
	for _, began := range []time.Time{t0, t0.Add(-time.Hour)} {
		if err := newStore(time.Hour, &now).Restore(ten(t), began); err != nil {
			t.Errorf("began %v: %v", began, err)
		}
	}
}

// A restored snapshot is no baseline: the first sync after boot is checked only
// for being non-empty, with or without a copy to restore. Later syncs are held
// to the limits, including after a narrowing of the restored snapshot.
func TestStoreRestoredIsNoBaseline(t *testing.T) {
	now := t0
	other := build(t, world{identities: people("q", 10), grants: readers(people("q", 10))})
	st := newStore(time.Hour, &now)
	if err := st.Restore(ten(t), t0); err != nil {
		t.Fatal(err)
	}
	st.Narrow(Narrowing{})
	<-st.Changed()
	if err := st.Swap(st.StartSync(), other); err != nil {
		t.Fatalf("first sync after restoring: %v", err)
	}
	if err := st.Swap(st.StartSync(), ten(t)); !errors.Is(err, ErrSwapRejected) {
		t.Fatalf("second sync escaped the limits: %v", err)
	}
}

// Narrowings recorded before a restore apply to it, and stay pending for a sync
// already in flight.
func TestStoreRestoreReplaysNarrowings(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)
	start := st.StartSync()
	id := ten(t).Data().Identities[0].ID
	st.Narrow(Narrowing{DeactivateIdentities: []string{id}})
	select {
	case <-st.Changed():
		t.Error("signalled with nothing live")
	default:
	}
	if err := st.Restore(ten(t), t0); err != nil {
		t.Fatal(err)
	}
	if _, ok := current(t, st).Identity(id); ok {
		t.Error("narrowing lost on restore")
	}
	if err := st.Swap(start, ten(t)); err != nil {
		t.Fatal(err)
	}
	if _, ok := current(t, st).Identity(id); ok {
		t.Error("narrowing lost on the sync after restore")
	}
}

// Every published change signals, without blocking when nobody is listening.
func TestStoreChangedCoalesces(t *testing.T) {
	now := t0
	st := newStore(time.Hour, &now)
	if err := st.Swap(st.StartSync(), ten(t)); err != nil {
		t.Fatal(err)
	}
	st.Narrow(Narrowing{})
	<-st.Changed()
	select {
	case <-st.Changed():
		t.Error("changes did not coalesce")
	default:
	}
	st.Narrow(Narrowing{})
	<-st.Changed()
}
