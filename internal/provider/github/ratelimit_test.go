package github

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/rurounijones/naraen/internal/provider"
	"github.com/rurounijones/naraen/internal/telemetry"
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
	p := f.provider("naraen-lfs")
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

// The installation token request and the Actions keys request wait out a
// rate limit like the API pages do, and the keys request still carries no
// credentials (the fake refuses one that does).
func TestTokenAndKeysWaitOutRateLimits(t *testing.T) {
	f, p, clock := limitedProvider(t)
	f.limits[tokenPath] = []refusal{{http.StatusForbidden, map[string]string{"Retry-After": "45"}, ""}}
	f.limits["/jwks"] = []refusal{{http.StatusTooManyRequests, nil, ""}}
	snap, err := p.FullSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := clock.waits(), []time.Duration{45 * time.Second, time.Minute}; !slices.Equal(got, want) {
		t.Errorf("waited %v, want %v", got, want)
	}
	if n := f.tokenCalls.Load(); n != 2 {
		t.Errorf("%d token requests, want 2", n)
	}
	if n := f.hitsFor("/jwks"); n != 2 {
		t.Errorf("%d keys requests, want 2", n)
	}
	if len(snap.Trusts()) != 1 {
		t.Errorf("trusts = %+v", snap.Trusts())
	}
}

// A refused token request that is not a rate limit fails the sync at once.
func TestTokenRefusedWithoutRateLimit(t *testing.T) {
	f, p, clock := limitedProvider(t)
	f.limits[tokenPath] = []refusal{{http.StatusForbidden, nil, `{"message":"Integration suspended"}`}}
	if _, err := p.FullSync(context.Background()); err == nil || !strings.Contains(err.Error(), "installation token: status 403") {
		t.Fatalf("err = %v", err)
	}
	if len(clock.waits()) != 0 || f.tokenCalls.Load() != 1 {
		t.Errorf("retried: waited %v, %d token requests", clock.waits(), f.tokenCalls.Load())
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
// a longer one short. Only the time by which a pause extends the hold is
// counted, so overlapping refusals count once.
func TestPauseOnlyExtends(t *testing.T) {
	clock := &fakeClock{now: syncNow}
	reader := sdkmetric.NewManualReader()
	c := &Client{Now: clock.Now, Rec: telemetry.NewRecorder(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))}
	ctx := context.Background()
	if r := c.pause(ctx, 2*time.Minute); !r.Equal(syncNow.Add(2 * time.Minute)) {
		t.Errorf("resume = %v, want two minutes on", r)
	}
	if r := c.pause(ctx, time.Minute); !r.Equal(syncNow.Add(2 * time.Minute)) {
		t.Errorf("shorter pause: resume = %v, want two minutes on", r)
	}
	if r := c.pause(ctx, 3*time.Minute); !r.Equal(syncNow.Add(3 * time.Minute)) {
		t.Errorf("longer pause: resume = %v, want three minutes on", r)
	}
	// Long after the hold ended, a new pause counts in full.
	clock.advance(10 * time.Minute)
	c.pause(ctx, time.Minute)
	// 2 minutes, then the 1 minute the longer pause added, then 1 minute.
	if got := waited(t, reader); got != 4*time.Minute {
		t.Errorf("counted %v held back, want 4m", got)
	}
}

// waited returns the lfs.sync.rate_limit_wait total the reader holds.
func waited(t *testing.T, reader *sdkmetric.ManualReader) time.Duration {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if s, ok := m.Data.(metricdata.Sum[float64]); ok && m.Name == telemetry.MetricSyncRateLimitWait {
				return time.Duration(s.DataPoints[0].Value * float64(time.Second))
			}
		}
	}
	return 0
}

// Each refusal is logged with the wait and when requests resume, the hold is
// counted, and a sync that gives up fails with provider.ErrRateLimited, so
// Run counts it under its own reason.
func TestRateLimitReported(t *testing.T) {
	secondary := refusal{http.StatusForbidden, nil, secondaryMessage}
	_, p, _ := limitedProvider(t, refusal{http.StatusTooManyRequests, map[string]string{"Retry-After": "30"}, ""})
	var logs bytes.Buffer
	reader := sdkmetric.NewManualReader()
	p.Client.Log = slog.New(slog.NewTextHandler(&logs, nil))
	p.Client.Rec = telemetry.NewRecorder(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if _, err := p.FullSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := `level=WARN msg="github rate limit: holding requests back" path=/orgs/acme/members wait=30s resume=` +
		syncNow.Add(30*time.Second).Format("2006-01-02T15:04:05.000Z07:00") + " attempt=1"
	if !strings.Contains(logs.String(), want) {
		t.Errorf("log:\n%s\nwant %s", logs.String(), want)
	}
	if got := waited(t, reader); got != 30*time.Second {
		t.Errorf("counted %v held back, want 30s", got)
	}

	_, p, _ = limitedProvider(t, secondary, secondary, secondary, secondary)
	_, err := p.FullSync(context.Background())
	if !errors.Is(err, provider.ErrRateLimited) {
		t.Errorf("gave up with %v, want ErrRateLimited", err)
	}
	if _, err := p.FullSync(context.Background()); !errors.Is(err, provider.ErrRateLimited) {
		t.Errorf("held back with %v, want ErrRateLimited", err)
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
