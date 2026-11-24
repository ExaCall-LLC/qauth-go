package qauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// ttlCache keeps answers briefly, so a change in qAuth (a role removed, a
// key revoked) takes effect soon. Concurrent asks for the same key share one
// call (even with the cache off). Only successful answers are kept; keys are
// hashes or ids, never raw tokens or API keys.
type ttlCache[T any] struct {
	mu       sync.Mutex
	ttl      time.Duration
	max      int
	now      func() time.Time
	items    map[string]cacheItem[T]
	inflight map[string]*flight[T]
}

type cacheItem[T any] struct {
	v     T
	until time.Time
}

type flight[T any] struct {
	done chan struct{}
	v    T
	err  error
}

func newTTLCache[T any](ttl time.Duration, max int, now func() time.Time) *ttlCache[T] {
	if max <= 0 {
		max = 10000
	}
	return &ttlCache[T]{ttl: ttl, max: max, now: now, items: map[string]cacheItem[T]{}, inflight: map[string]*flight[T]{}}
}

// load answers the kept value for k, or calls fn once for every concurrent
// asker and keeps a successful answer (when keep says so). A waiting asker
// stops waiting when its own ctx ends.
func (c *ttlCache[T]) load(ctx context.Context, k string, fn func() (T, error), keep func(T) bool) (T, error) {
	c.mu.Lock()
	if it, ok := c.items[k]; ok {
		if c.now().Before(it.until) {
			c.mu.Unlock()
			return it.v, nil
		}
		delete(c.items, k)
	}
	if f, ok := c.inflight[k]; ok {
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.v, f.err
		case <-ctx.Done():
			var zero T
			return zero, &Error{Code: CodeUnavailable, Message: "qAuth did not answer in time.", Err: ctx.Err()}
		}
	}
	f := &flight[T]{done: make(chan struct{})}
	c.inflight[k] = f
	c.mu.Unlock()

	f.v, f.err = fn()
	c.mu.Lock()
	delete(c.inflight, k)
	if f.err == nil && c.ttl > 0 && (keep == nil || keep(f.v)) {
		c.putLocked(k, f.v)
	}
	c.mu.Unlock()
	close(f.done)
	return f.v, f.err
}

func (c *ttlCache[T]) putLocked(k string, v T) {
	now := c.now()
	if len(c.items) >= c.max {
		for key, it := range c.items {
			if !now.Before(it.until) {
				delete(c.items, key)
			}
		}
		for key := range c.items { // still full: drop any one
			if len(c.items) < c.max {
				break
			}
			delete(c.items, key)
		}
	}
	c.items[k] = cacheItem[T]{v: v, until: now.Add(c.ttl)}
}

// forget drops every entry whose key starts with prefix ("" = everything).
func (c *ttlCache[T]) forget(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.items {
		if strings.HasPrefix(k, prefix) {
			delete(c.items, k)
		}
	}
}

func (c *ttlCache[T]) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
