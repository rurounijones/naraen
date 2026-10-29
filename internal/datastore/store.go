package datastore

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrNotReady is returned until the first full sync has been swapped in.
	ErrNotReady = errors.New("datastore: no snapshot loaded")
	// ErrStale is returned when the snapshot is older than the configured maximum age.
	ErrStale = errors.New("datastore: snapshot too old")
	// ErrSwapRejected is returned when a new snapshot fails validation.
	ErrSwapRejected = errors.New("datastore: snapshot rejected")
)

// Limits bound how much one full sync may change access relative to the live
// snapshot. Each kind of change is allowed Slack changes plus a share of the
// live count, so small datastores are not held to percentages they cannot
// meet, and a datastore that starts small cannot then be replaced wholesale.
type Limits struct {
	// Slack is the number of changes of each kind always allowed.
	Slack int
	// MaxShrink is the share of active identities or grants a sync may remove.
	MaxShrink float64
	// MaxGrow is the share of active identities or grants a sync may add.
	MaxGrow float64
	// MaxRaise is the share of grants whose level a sync may raise. Raising
	// a level is the quietest way to widen access, so it is held tightest.
	MaxRaise float64
}

// DefaultLimits are the change limits the server runs with.
var DefaultLimits = Limits{Slack: 10, MaxShrink: 0.2, MaxGrow: 0.5, MaxRaise: 0.1}

// SyncStart records when a full sync began reading its source. A snapshot is
// only as fresh as the moment its data was read, and narrowings that arrive
// while the sync runs must be replayed on top of it.
type SyncStart struct {
	seq uint64
	at  time.Time
}

type published struct {
	snap  *Snapshot
	start SyncStart
}

type narrowing struct {
	seq uint64
	n   Narrowing
}

// Store publishes the current snapshot atomically. Readers see either the old or
// the new snapshot, never a partial one. All writes go through one mutex, so a
// full sync and a webhook delta can never lose each other's changes.
type Store struct {
	cur    atomic.Pointer[published]
	maxAge time.Duration
	limits Limits

	mu       sync.Mutex
	seq      uint64      // narrowings recorded so far
	pending  []narrowing // narrowings an in-flight sync may not have seen
	approved bool        // the next swap may exceed the limits

	// Now is replaceable in tests.
	Now func() time.Time
}

// NewStore creates a Store that refuses to serve a snapshot whose sync began
// more than maxAge ago, and rejects swaps that exceed limits.
func NewStore(maxAge time.Duration, limits Limits) *Store {
	return &Store{maxAge: maxAge, limits: limits, Now: time.Now}
}

// Current returns the live snapshot, or an error if there is none or it is stale.
// Callers must treat any error as "deny".
func (s *Store) Current() (*Snapshot, error) {
	p := s.cur.Load()
	if p == nil {
		return nil, ErrNotReady
	}
	// Age is measured from this process's clock at the start of the sync, never
	// from a timestamp inside the data, which a provider bug or skewed clock
	// could put in the future.
	if s.Now().Sub(p.start.at) > s.maxAge {
		return nil, ErrStale
	}
	return p.snap, nil
}

// Ready reports whether Current would return a snapshot.
func (s *Store) Ready() bool {
	_, err := s.Current()
	return err == nil
}

// StartSync must be called before a full sync reads its source. The result is
// passed to Swap.
func (s *Store) StartSync() SyncStart {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SyncStart{seq: s.seq, at: s.Now()}
}

// Swap publishes next, the result of the sync that began at start. Narrowings
// recorded since start are replayed onto it first. It is rejected if it is
// empty, if a sync that began later has already been published, or if it
// changes access by more than the limits allow (unless ApproveNextSwap was
// called). The first snapshot has no baseline and is checked only for being
// non-empty.
func (s *Store) Swap(start SyncStart, next *Snapshot) error {
	if next == nil {
		return fmt.Errorf("%w: nil snapshot", ErrSwapRejected)
	}
	if len(next.identities) == 0 || len(next.repos) == 0 {
		return fmt.Errorf("%w: no identities or no repos", ErrSwapRejected)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.cur.Load()
	if old != nil && (start.seq < old.start.seq || start.at.Before(old.start.at)) {
		return fmt.Errorf("%w: superseded by a sync that started later", ErrSwapRejected)
	}
	for _, p := range s.pending {
		if p.seq > start.seq {
			next = next.narrowed(p.n)
		}
	}
	if old != nil && !s.approved {
		if err := s.limits.check(old.snap, next); err != nil {
			return err
		}
	}
	s.approved = false
	s.cur.Store(&published{snap: next, start: start})
	// Every later swap starts at or after start, so it has seen these.
	s.pending = slices.DeleteFunc(s.pending, func(p narrowing) bool { return p.seq <= start.seq })
	return nil
}

// ApproveNextSwap lets the next successful Swap exceed the change limits. It
// is the operator's override once a rejected change has been reviewed and is
// known to be real (a reorg, a mass offboarding). Structural validation and
// supersession still apply.
func (s *Store) ApproveNextSwap() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.approved = true
}

// Narrow applies n to the live snapshot at once, and records it so that a
// full sync already in flight cannot undo it when it is swapped in.
func (s *Store) Narrow(n Narrowing) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	s.pending = append(s.pending, narrowing{seq: s.seq, n: n})
	if p := s.cur.Load(); p != nil {
		s.cur.Store(&published{snap: p.snap.narrowed(n), start: p.start})
	}
}

// change counts how next differs from old.
type change struct {
	identitiesRemoved, identitiesAdded       int
	grantsRemoved, grantsAdded, grantsRaised int
}

func diff(old, next *Snapshot) change {
	var c change
	for id, i := range old.identities {
		if n, ok := next.identities[id]; i.Active && (!ok || !n.Active) {
			c.identitiesRemoved++
		}
	}
	for id, n := range next.identities {
		if i, ok := old.identities[id]; n.Active && (!ok || !i.Active) {
			c.identitiesAdded++
		}
	}
	for k, l := range old.grants {
		if n, ok := next.grants[k]; !ok {
			c.grantsRemoved++
		} else if n > l {
			c.grantsRaised++
		}
	}
	for k := range next.grants {
		if _, ok := old.grants[k]; !ok {
			c.grantsAdded++
		}
	}
	return c
}

func activeIdentities(s *Snapshot) int {
	n := 0
	for _, i := range s.identities {
		if i.Active {
			n++
		}
	}
	return n
}

func (l Limits) check(old, next *Snapshot) error {
	c := diff(old, next)
	ids, grants := activeIdentities(old), len(old.grants)
	for _, v := range []struct {
		what  string
		n, of int
		share float64
	}{
		{"identities removed", c.identitiesRemoved, ids, l.MaxShrink},
		{"identities added", c.identitiesAdded, ids, l.MaxGrow},
		{"grants removed", c.grantsRemoved, grants, l.MaxShrink},
		{"grants added", c.grantsAdded, grants, l.MaxGrow},
		{"grants raised", c.grantsRaised, grants, l.MaxRaise},
	} {
		if float64(v.n) > float64(l.Slack)+v.share*float64(v.of) {
			return fmt.Errorf("%w: %s %d of %d exceeds the limit", ErrSwapRejected, v.what, v.n, v.of)
		}
	}
	return nil
}
