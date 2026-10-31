package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rurounijones/naraen/internal/datastore"
)

// A second sync of an unchanged organisation is answered entirely with 304s
// and builds the same snapshot from the cached pages. A page that changes is
// read in full again, and only that page.
func TestFullSyncReusesUnchangedPages(t *testing.T) {
	f := newFakeGitHub(t)
	aliceFP, deployFP := f.organisation(t)
	f.etags = true
	p := f.provider("naraen-lfs")
	if _, err := p.FullSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Two repos pages, members, two members' keys, and two repos'
	// collaborators and deploy keys.
	const pages = 9
	if full, unchanged := f.full.Load(), f.unchanged.Load(); full != pages || unchanged != 0 {
		t.Fatalf("first sync: %d full, %d unchanged", full, unchanged)
	}

	snap, err := p.FullSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if full, unchanged := f.full.Load(), f.unchanged.Load(); full != pages || unchanged != pages {
		t.Fatalf("unchanged sync: %d full, %d unchanged", full, unchanged)
	}
	if id, ok := snap.KeyOwner(aliceFP); !ok || id.ID != "gh-user-1" {
		t.Errorf("alice's key from the cache = %+v, %v", id, ok)
	}
	if id, ok := snap.KeyOwner(deployFP); !ok || id.ID != "gh-deploy-key-10" {
		t.Errorf("deploy key from the cache = %+v, %v", id, ok)
	}
	if _, ok := snap.RepoByPath("acme/other"); !ok {
		t.Error("second repos page lost: its Link header was not reused")
	}
	for _, g := range []struct {
		id, repo string
		want     datastore.Level
	}{
		{"gh-user-1", "100", datastore.LevelWrite},
		{"gh-user-2", "200", datastore.LevelRead},
		{"gh-deploy-key-11", "200", datastore.LevelWrite},
	} {
		if got := snap.GrantLevel(g.id, g.repo); got != g.want {
			t.Errorf("%s on %s from the cache = %v, want %v", g.id, g.repo, got, g.want)
		}
	}

	bobKey, bobFP := deployKey(t)
	f.routes["/users/bob/keys?per_page=100"] = `[{"id":6,"key":"` + bobKey + `"}]`
	snap, err = p.FullSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if full := f.full.Load(); full != pages+1 {
		t.Errorf("one changed page: %d full responses in all, want %d", full, pages+1)
	}
	if id, ok := snap.KeyOwner(bobFP); !ok || id.ID != "gh-user-2" {
		t.Errorf("bob's new key = %+v, %v", id, ok)
	}
}

// A page whose context changed is not reused even when GitHub reports it
// unchanged: acme/other deleted and recreated with the same collaborators
// and deploy key answers with the same bodies, but the grants belong to the
// new repo ID.
func TestCacheIsScopedToTheRepo(t *testing.T) {
	f := newFakeGitHub(t)
	f.organisation(t)
	f.etags = true
	p := f.provider("")
	if _, err := p.FullSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.routes["/installation/repositories?per_page=100&page=2"] = `{"total_count":2,"repositories":[{"id":300,"full_name":"acme/other"}]}`
	snap, err := p.FullSync(context.Background())
	if err != nil {
		t.Fatalf("sync after the repo was recreated: %v", err)
	}
	if got := snap.GrantLevel("gh-user-2", "300"); got != datastore.LevelRead {
		t.Errorf("bob on the new repo = %v", got)
	}
	if got := snap.GrantLevel("gh-deploy-key-11", "300"); got != datastore.LevelWrite {
		t.Errorf("deploy key on the new repo = %v", got)
	}
}

// A complete sync drops the pages it did not use; a failed one drops
// nothing, since it may have stopped before reaching pages still current.
func TestCacheSweptAfterCompleteSyncOnly(t *testing.T) {
	f := newFakeGitHub(t)
	f.organisation(t)
	f.etags = true
	p := f.provider("")
	if _, err := p.FullSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(p.cache.keys.entries); n != 2 {
		t.Fatalf("%d members' keys cached", n)
	}
	// bob leaves, and the sync then fails at the deploy keys.
	f.routes["/orgs/acme/members?per_page=100"] = `[{"id":1,"login":"alice"}]`
	f.routes["/repos/acme/Assets/collaborators?affiliation=all&per_page=100"] = `[{"id":1,"login":"alice","permissions":{"push":true}}]`
	keys := f.routes["/repos/acme/other/keys?per_page=100"]
	delete(f.routes, "/repos/acme/other/keys?per_page=100")
	if _, err := p.FullSync(context.Background()); err == nil {
		t.Fatal("sync succeeded without deploy keys")
	}
	if n := len(p.cache.keys.entries); n != 2 {
		t.Errorf("failed sync left %d members' keys cached, want both", n)
	}
	f.edit(func() { f.routes["/repos/acme/other/keys?per_page=100"] = keys })
	if _, err := p.FullSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(p.cache.keys.entries); n != 1 {
		t.Errorf("complete sync left %d members' keys cached, want alice's alone", n)
	}
	for name, n := range map[string]int{
		"repos": len(p.cache.repos.entries), "members": len(p.cache.members.entries),
		"collaborators": len(p.cache.collaborators.entries), "deploy keys": len(p.cache.deployKeys.entries),
	} {
		if n == 0 {
			t.Errorf("no %s pages cached", name)
		}
	}
}

// Without an ETag nothing is cached, and a 304 to a request that sent none is
// an error rather than an empty page.
func TestUncachedResponses(t *testing.T) {
	f := newFakeGitHub(t)
	f.organisation(t)
	p := f.provider("")
	if _, err := p.FullSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(p.cache.keys.entries); n != 0 {
		t.Errorf("%d pages cached without ETags", n)
	}
	f.status["/users/bob/keys?per_page=100"] = http.StatusNotModified
	if _, err := p.FullSync(context.Background()); err == nil {
		t.Error("304 without an ETag accepted")
	}
}

// Members' keys and repos are read concurrently, but never more than
// syncConcurrency requests at a time.
func TestFullSyncBoundsConcurrency(t *testing.T) {
	f := newFakeGitHub(t)
	f.organisation(t)
	var members string
	for i := range 3 * syncConcurrency {
		login := fmt.Sprintf("m%d", i)
		members += fmt.Sprintf(`,{"id":%d,"login":%q}`, 1000+i, login)
		f.routes["/users/"+login+"/keys?per_page=100"] = `[]`
	}
	f.routes["/orgs/acme/members?per_page=100"] = `[{"id":1,"login":"alice"},{"id":2,"login":"bob"}` + members + `]`
	f.delay = 5 * time.Millisecond
	if _, err := f.provider("").FullSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := f.maxInFlight.Load(); n < 2 || n > syncConcurrency {
		t.Errorf("%d requests in flight at most, want between 2 and %d", n, syncConcurrency)
	}
}

// each runs syncConcurrency calls at once, and no more.
func TestEachRunsConcurrently(t *testing.T) {
	var running, peak atomic.Int32
	var ready sync.WaitGroup
	ready.Add(syncConcurrency)
	err := each(context.Background(), 3*syncConcurrency, func(_ context.Context, i int) error {
		raise(&peak, running.Add(1))
		defer running.Add(-1)
		if i < syncConcurrency {
			// The first calls wait for each other, which only works if
			// they run at the same time.
			ready.Done()
			done := make(chan struct{})
			go func() { ready.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				return errors.New("calls did not run concurrently")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if p := peak.Load(); p != syncConcurrency {
		t.Errorf("peak concurrency %d, want %d", p, syncConcurrency)
	}
}

// The first error is returned, the calls still running see their context
// cancelled, and no further calls start.
func TestEachStopsAtFirstError(t *testing.T) {
	boom := errors.New("boom")
	var calls atomic.Int32
	err := each(context.Background(), 100, func(ctx context.Context, i int) error {
		calls.Add(1)
		if i == 0 {
			return boom
		}
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the first error", err)
	}
	if n := calls.Load(); n > syncConcurrency {
		t.Errorf("%d calls started after the error", n)
	}
	if err := each(context.Background(), 0, func(context.Context, int) error { return boom }); err != nil {
		t.Errorf("no work: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := each(ctx, 3, func(context.Context, int) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: %v", err)
	}
}
