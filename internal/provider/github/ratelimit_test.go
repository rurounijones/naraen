package github

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock stands in for the client's clock: Sleep moves it on at once and
// records the wait.
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	c.slept = append(c.slept, d)
	return nil
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) waits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.slept)
}

// limitedProvider is the fake organisation with the members listing refused
// by rs before it is served, read by a provider on a fake clock.
func limitedProvider(t *testing.T, rs ...refusal) (*fakeGitHub, *Provider, *fakeClock) {
	t.Helper()
	f := newFakeGitHub(t)
	f.organisation(t)
	f.limits[membersPage] = rs
	p := f.provider("")
	clock := &fakeClock{now: syncNow}
	p.Client.Now, p.Client.Sleep = clock.Now, clock.Sleep
	return f, p, clock
}

const membersPage = "/orgs/acme/members?per_page=100"

const secondaryMessage = `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`

func epoch(d time.Duration) string { return strconv.FormatInt(syncNow.Add(d).Unix(), 10) }

// A request refused for the rate limit is retried after the wait GitHub asks
// for, and the sync then succeeds.
func TestRateLimitWaitsAndRetries(t *testing.T) {
	secondary := refusal{http.StatusForbidden, nil, secondaryMessage}
	for name, tt := range map[string]struct {
		refusals []refusal
		want     []time.Duration
	}{
		"403 with Retry-After": {
			[]refusal{{http.StatusForbidden, map[string]string{"Retry-After": "30"}, secondaryMessage}},
			[]time.Duration{30 * time.Second},
		},
		"429 with Retry-After at the longest wait": {
			[]refusal{{http.StatusTooManyRequests, map[string]string{"Retry-After": "300"}, ""}},
			[]time.Duration{maxRateLimitWait},
		},
		"Retry-After before the reset time": {
			[]refusal{{http.StatusForbidden, map[string]string{
				"Retry-After": "20", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": epoch(200 * time.Second),
			}, ""}},
			[]time.Duration{20 * time.Second},
		},
		"primary limit until the reset": {
			[]refusal{{http.StatusForbidden, map[string]string{
				"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": epoch(90 * time.Second),
			}, ""}},
			[]time.Duration{90 * time.Second},
		},
		"reset already passed": {
			[]refusal{{http.StatusTooManyRequests, map[string]string{
				"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": epoch(-10 * time.Second),
			}, ""}},
			nil,
		},
		"reset without the remaining count at zero": {
			[]refusal{{http.StatusTooManyRequests, map[string]string{
				"X-RateLimit-Remaining": "7", "X-RateLimit-Reset": epoch(90 * time.Second),
			}, ""}},
			[]time.Duration{time.Minute},
		},
		"secondary limit without headers, backing off": {
			[]refusal{secondary, secondary, secondary},
			[]time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute},
		},
		"429 without headers": {
			[]refusal{{http.StatusTooManyRequests, nil, ""}},
			[]time.Duration{time.Minute},
		},
		"malformed Retry-After": {
			[]refusal{{http.StatusTooManyRequests, map[string]string{"Retry-After": "soon"}, ""}},
			[]time.Duration{time.Minute},
		},
		"malformed reset": {
			[]refusal{{http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "x"}, ""}},
			[]time.Duration{time.Minute},
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, p, clock := limitedProvider(t, tt.refusals...)
			if _, err := p.FullSync(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := clock.waits(); !slices.Equal(got, tt.want) {
				t.Errorf("waited %v, want %v", got, tt.want)
			}
			if n := f.hitsFor(membersPage); n != len(tt.refusals)+1 {
				t.Errorf("%d requests for the members page, want %d", n, len(tt.refusals)+1)
			}
		})
	}
}

// After maxRateLimitRetries retries the sync fails, and the last wait still
// holds: a later sync sends nothing until it has passed.
func TestRateLimitGivesUp(t *testing.T) {
	secondary := refusal{http.StatusForbidden, nil, secondaryMessage}
	f, p, clock := limitedProvider(t, secondary, secondary, secondary, secondary)
	_, err := p.FullSync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rate limited, retry after 8m0s") {
		t.Fatalf("err = %v", err)
	}
	if got, want := clock.waits(), []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute}; !slices.Equal(got, want) {
		t.Errorf("waited %v, want %v", got, want)
	}
	requireHeldBack(t, f, p, clock, 8*time.Minute)
}

// A wait longer than maxRateLimitWait fails the sync at once rather than
// holding it, and holds back later syncs until it has passed.
func TestRateLimitTooLongToWait(t *testing.T) {
	f, p, clock := limitedProvider(t, refusal{http.StatusForbidden, map[string]string{
		"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": epoch(maxRateLimitWait + time.Second),
	}, ""})
	_, err := p.FullSync(context.Background())
	if want := "rate limited until " + syncNow.Add(maxRateLimitWait+time.Second).Format(time.RFC3339); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want %q", err, want)
	}
	if got := clock.waits(); len(got) != 0 {
		t.Errorf("waited %v", got)
	}
	requireHeldBack(t, f, p, clock, maxRateLimitWait+time.Second)
}

// requireHeldBack checks that a sync started now sends no request to GitHub,
// and one started after pause succeeds.
func requireHeldBack(t *testing.T, f *fakeGitHub, p *Provider, clock *fakeClock, pause time.Duration) {
	t.Helper()
	before := f.hitsFor("/installation/repositories?per_page=100")
	if _, err := p.FullSync(context.Background()); err == nil || !strings.Contains(err.Error(), "rate limited until") {
		t.Fatalf("sync while limited: %v", err)
	}
	if n := f.hitsFor("/installation/repositories?per_page=100"); n != before {
		t.Errorf("a sync while limited sent %d requests", n-before)
	}
	clock.advance(pause)
	if _, err := p.FullSync(context.Background()); err != nil {
		t.Errorf("sync after the limit: %v", err)
	}
}

// A 403 that does not say it is a rate limit is a missing permission, and
// another status is never a rate limit: both fail at once.
func TestRefusalsThatAreNotRateLimits(t *testing.T) {
	for name, r := range map[string]refusal{
		"403 forbidden":        {http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "4999"}, `{"message":"Resource not accessible by integration"}`},
		"503 with Retry-After": {http.StatusServiceUnavailable, map[string]string{"Retry-After": "1"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			f, p, clock := limitedProvider(t, r)
			_, err := p.FullSync(context.Background())
			if err == nil || !strings.Contains(err.Error(), "status "+strconv.Itoa(r.status)) {
				t.Fatalf("err = %v", err)
			}
			if len(clock.waits()) != 0 || f.hitsFor(membersPage) != 1 {
				t.Errorf("retried: waited %v, %d requests", clock.waits(), f.hitsFor(membersPage))
			}
		})
	}
}

// A wait cut short, as by shutdown, fails the sync.
func TestRateLimitWaitInterrupted(t *testing.T) {
	_, p, _ := limitedProvider(t, refusal{http.StatusTooManyRequests, map[string]string{"Retry-After": "30"}, ""})
	p.Client.Sleep = func(context.Context, time.Duration) error { return context.Canceled }
	if _, err := p.FullSync(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// A pause only ever grows: a shorter wait from another request does not cut
// a longer one short.
func TestPauseOnlyExtends(t *testing.T) {
	c := &Client{Now: func() time.Time { return syncNow }}
	c.pause(2 * time.Minute)
	c.pause(time.Minute)
	if !c.resume.Equal(syncNow.Add(2 * time.Minute)) {
		t.Errorf("resume = %v, want two minutes on", c.resume)
	}
	c.pause(3 * time.Minute)
	if !c.resume.Equal(syncNow.Add(3 * time.Minute)) {
		t.Errorf("resume = %v, want three minutes on", c.resume)
	}
}

func TestSleep(t *testing.T) {
	if err := Sleep(context.Background(), 0); err != nil {
		t.Errorf("sleep: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled sleep: %v", err)
	}
}
