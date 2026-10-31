package github

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
)

// syncConcurrency bounds the requests one sync has in flight. GitHub asks
// integrations to stay well under its secondary rate limits (at most 100
// concurrent requests, and 900 points a minute for REST, a GET costing one),
// and at typical API latency four requests at a time already approach 900 a
// minute; more would only trade sync time for refused requests.
const syncConcurrency = 4

// each runs fn for every index below n, at most syncConcurrency at a time,
// and returns the first error. After an error no further calls start, and the
// context the running ones were given is cancelled.
func each(ctx context.Context, n int, fn func(context.Context, int) error) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var next atomic.Int64
	var wg sync.WaitGroup
	for range min(n, syncConcurrency) {
		wg.Go(func() {
			for ctx.Err() == nil {
				i := int(next.Add(1)) - 1
				if i >= n {
					return
				}
				if err := fn(ctx, i); err != nil {
					cancel(err)
				}
			}
		})
	}
	wg.Wait()
	return context.Cause(ctx)
}

// pageCache remembers, for each page a sync read in full, its ETag, its Link
// header and what parse made of it. The next sync sends the ETag back as
// If-None-Match and, on 304 Not Modified, reuses the parsed page. GitHub does
// not count a 304 against the App's primary rate limit, so a sync of an
// organisation that has not changed costs almost nothing.
//
// It holds parsed pages rather than bodies: with affiliation=all every repo's
// collaborator listing names every member with access, and the bodies for a
// large organisation would not fit a small instance's memory.
type pageCache[T any] struct {
	mu      sync.Mutex
	entries map[string]*cachedPage[T]
}

type cachedPage[T any] struct {
	etag, link string
	value      T
	// used reports whether the current sync has used the page.
	used bool
}

// begin starts a sync: no page has been used by it yet.
func (c *pageCache[T]) begin() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.entries {
		e.used = false
	}
}

// get returns the page cached under key, marking it used.
func (c *pageCache[T]) get(key string) cachedPage[T] {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return cachedPage[T]{}
	}
	e.used = true
	return *e
}

func (c *pageCache[T]) put(key string, page cachedPage[T]) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]*cachedPage[T]{}
	}
	c.entries[key] = &page
}

// sweep drops the pages the sync did not use, such as a departed member's
// keys, so the cache holds one organisation's worth of pages and no more.
func (c *pageCache[T]) sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if !e.used {
			delete(c.entries, k)
		}
	}
}

// fetch reads path and every following page named by the Link header, and
// returns what parse made of each page, reusing cached pages GitHub reports
// unchanged. A next link must stay on BaseURL, so a response cannot send the
// installation token anywhere else.
//
// scope names whatever parse depends on besides the body, such as the repo or
// identity it attributes results to, and is part of the cache key: a repo
// deleted and recreated under the same name, with the same collaborators,
// answers with the same body and ETag, and must not inherit the old repo's
// grants.
func fetch[T any](ctx context.Context, c *Client, cache *pageCache[T], scope, path string, parse func(io.Reader) (T, error)) ([]T, error) {
	next := c.BaseURL + path
	var out []T
	for range maxPages {
		key := scope + " " + next
		// A page is cached only with its ETag, and get reports 304 only for a
		// request that sent one, so not modified always has a page to reuse.
		page := cache.get(key)
		resp, err := c.get(ctx, next, page.etag)
		if err != nil {
			return nil, err
		}
		if !resp.notModified {
			v, err := parse(bytes.NewReader(resp.body))
			if err != nil {
				return nil, fmt.Errorf("github: %s: %w", path, err)
			}
			page = cachedPage[T]{etag: resp.etag, link: resp.link, value: v, used: true}
			if resp.etag != "" {
				cache.put(key, page)
			}
		}
		out = append(out, page.value)
		next = nextLink(page.link)
		if next == "" {
			return out, nil
		}
		if !strings.HasPrefix(next, c.BaseURL+"/") {
			return nil, fmt.Errorf("github: %s: next page outside the API: %q", path, next)
		}
	}
	return nil, fmt.Errorf("github: %s: more than %d pages", path, maxPages)
}
