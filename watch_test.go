package qauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeStreams is qAuth's session stream and state as a test drives them:
// each opening answers what next says; push sends an event on the open one.
type fakeStreams struct {
	opened, states atomic.Int32
	next           atomic.Value // func(n int32) int: the status of opening n (1-based)
	ended          atomic.Value // the state's ended ("" = open)
	events         chan string  // raw "event: x\ndata: y" blocks for the open stream
}

func newFake(t *testing.T) (*fakeStreams, *Client) {
	t.Helper()
	f := &fakeStreams{events: make(chan string, 8)}
	f.setNext(func(int32) int { return 200 })
	f.ended.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/me/sessions/s1/state":
			f.states.Add(1)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"success":true,"data":{"sessionId":"s1","idleSecondsLeft":-1,"maxSecondsLeft":-1,"ended":%q,"pollSeconds":1}}`, f.ended.Load())
		case "/v1/me/sessions/s1/events":
			n := f.opened.Add(1)
			if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Query().Get("client") != "web" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if code := f.next.Load().(func(int32) int)(n); code != 200 {
				if code == http.StatusTooManyRequests {
					w.Header().Set("Retry-After", "1")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				fmt.Fprint(w, `{"success":false,"error":{"code":"X","message":"x"}}`)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			fl := w.(http.Flusher)
			fmt.Fprint(w, "event: ready\ndata: {\"pollSeconds\":1,\"heartbeatSeconds\":5}\n\n")
			fl.Flush()
			for {
				select {
				case <-r.Context().Done():
					return
				case ev := <-f.events:
					if ev == "close" {
						return
					}
					fmt.Fprint(w, ev+"\n\n")
					fl.Flush()
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func (f *fakeStreams) setNext(g func(int32) int) { f.next.Store(g) }

func waitDone(t *testing.T, ctx context.Context, within time.Duration) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(within):
		t.Fatal("the watch did not end in time")
	}
}

func eventually(t *testing.T, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("not in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWatchEndsTheContextAtOnce(t *testing.T) {
	f, c := newFake(t)
	var told atomic.Value
	ctx, stop := c.As("tok").Account.Sessions.Watch(context.Background(), "s1", WatchOptions{ClientID: "web", OnEnded: func(r string) { told.Store(r) }})
	defer stop()
	eventually(t, time.Second, func() bool { return f.opened.Load() == 1 })
	time.Sleep(50 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatal("ended before the session did")
	}
	start := time.Now()
	f.events <- "event: ended\ndata: {\"reason\":\"suspended\"}"
	waitDone(t, ctx, time.Second)
	if SessionEnded(ctx) != "suspended" || told.Load() != "suspended" {
		t.Fatalf("why: %q / %v (%v)", SessionEnded(ctx), told.Load(), context.Cause(ctx))
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("took %v", d)
	}
}

func TestWatchReconnectsAndPollsMeanwhile(t *testing.T) {
	f, c := newFake(t)
	// the second opening is refused (too many streams), the third works
	f.setNext(func(n int32) int {
		if n == 2 {
			return http.StatusTooManyRequests
		}
		return 200
	})
	ctx, stop := c.As("tok").Account.Sessions.Watch(context.Background(), "s1", WatchOptions{ClientID: "web", MaxBackoff: 2 * time.Second})
	defer stop()
	eventually(t, time.Second, func() bool { return f.opened.Load() == 1 })
	f.events <- "event: reconnect\ndata: {}" // qAuth: open again, at once
	eventually(t, time.Second, func() bool { return f.opened.Load() == 2 })
	// refused: it polls the state meanwhile (pollSeconds 1) and tries again
	eventually(t, 3*time.Second, func() bool { return f.states.Load() >= 1 })
	eventually(t, 4*time.Second, func() bool { return f.opened.Load() == 3 })
	if ctx.Err() != nil {
		t.Fatal(context.Cause(ctx))
	}
	// ended while the stream is down: the poll sees it
	f.setNext(func(int32) int { return http.StatusServiceUnavailable })
	f.events <- "close"
	f.ended.Store("idle")
	waitDone(t, ctx, 4*time.Second)
	if SessionEnded(ctx) != "idle" {
		t.Fatalf("why: %v", context.Cause(ctx))
	}
}

func TestWatchTokenRefusedAndStop(t *testing.T) {
	f, c := newFake(t)
	f.setNext(func(int32) int { return http.StatusUnauthorized })
	ctx, stop := c.As("tok").Account.Sessions.Watch(context.Background(), "s1", WatchOptions{ClientID: "web"})
	defer stop()
	waitDone(t, ctx, time.Second)
	if !errors.Is(context.Cause(ctx), ErrTokenRefused) || SessionEnded(ctx) != "" {
		t.Fatalf("cause: %v", context.Cause(ctx))
	}
	// stop: the context ends, not because of the session
	f.setNext(func(int32) int { return 200 })
	ctx2, stop2 := c.As("tok").Account.Sessions.Watch(context.Background(), "s1", WatchOptions{ClientID: "web"})
	eventually(t, time.Second, func() bool { return f.opened.Load() >= 2 })
	stop2()
	waitDone(t, ctx2, time.Second)
	if SessionEnded(ctx2) != "" || !errors.Is(context.Cause(ctx2), context.Canceled) {
		t.Fatalf("stopped: %v", context.Cause(ctx2))
	}
}

// Against the real routes: signing the session out elsewhere ends the
// watch at once (keep it last: it ends cafe-admin's first session).
func TestWatchAgainstTheServer(t *testing.T) {
	seed := liveSeed(t)
	c, err := New(seed.BaseURL)
	if err != nil {
		t.Fatal(err)
	}
	me := c.As("cafe-admin-token").Account
	ctx, stop := me.Sessions.Watch(context.Background(), "sess-cafe-admin-1", WatchOptions{ClientID: "cid-live"})
	defer stop()
	time.Sleep(300 * time.Millisecond) // the stream is open
	if ctx.Err() != nil {
		t.Fatal(context.Cause(ctx))
	}
	start := time.Now()
	if err := me.Sessions.End(context.Background(), "sess-cafe-admin-1"); err != nil {
		t.Fatal(err)
	}
	waitDone(t, ctx, 2*time.Second)
	if SessionEnded(ctx) != "signed_out" {
		t.Fatalf("why: %v", context.Cause(ctx))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
	}
}
