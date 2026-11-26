package qauth

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Instant sign-out for app backends: Watch keeps qAuth's session stream
// open (GET /v1/me/sessions/{sid}/events) and cancels a context the moment
// the session ends, for any reason (signed out on another device, by an
// admin, suspended, idle, ...). Use it for what your backend holds open for
// the person (a websocket, a server stream, a long job): run it under the
// context and it stops with the session.
//
//	ctx, stop := me.Account.Sessions.Watch(r.Context(), sid, qauth.WatchOptions{ClientID: "my-app"})
//	defer stop()
//	go pump(ctx, ws) // ends when the session does
//	<-ctx.Done()
//	if why := qauth.SessionEnded(ctx); why != "" { ws.Close(...) }
//
// It reconnects with backoff, and while the stream is down it asks for the
// session's state every poll interval (qAuth's sessionPollSeconds unless
// you set one). The person's access token is the one the Person was made
// with: when qAuth refuses it (expired, or the session is over) the context
// ends with ErrTokenRefused; watch again with a fresh token.

// SessionEndedError is the cause of a watched context's end when the
// session ended; Reason says why (signed_out, idle, max_length,
// client_removed, access_removed, suspended, replaced).
type SessionEndedError struct{ Reason string }

func (e *SessionEndedError) Error() string { return "qauth: the session ended (" + e.Reason + ")" }

// ErrTokenRefused ends a watch whose access token qAuth no longer accepts
// (expired, or its session is over).
var ErrTokenRefused = errors.New("qauth: the access token was refused")

// SessionEnded says why a context from Watch ended ("" = not because the
// session ended: still running, stopped, or the token refused).
func SessionEnded(ctx context.Context) string {
	var e *SessionEndedError
	if errors.As(context.Cause(ctx), &e) {
		return e.Reason
	}
	return ""
}

// WatchOptions tune Watch.
type WatchOptions struct {
	// ClientID: your OAuth client_id (needed with single sign-on when the
	// token names no client).
	ClientID string
	// PollInterval: how often to ask while the stream is down. Default:
	// qAuth's sessionPollSeconds, else 45 seconds.
	PollInterval time.Duration
	// MaxBackoff: the longest wait between reconnects. Default 60 seconds.
	MaxBackoff time.Duration
	// OnEnded, when set, is called once with why the session ended (before
	// the context is cancelled).
	OnEnded func(reason string)
}

// Watch returns a context that ends when the session ends (cause
// *SessionEndedError), when qAuth refuses the token (ErrTokenRefused), or
// when you call stop or ctx ends.
func (x *Sessions) Watch(ctx context.Context, sessionID string, o WatchOptions) (context.Context, context.CancelFunc) {
	wctx, cancel := context.WithCancelCause(ctx)
	w := &watcher{x: x, sid: sessionID, o: o, cancel: cancel}
	if w.o.MaxBackoff <= 0 {
		w.o.MaxBackoff = 60 * time.Second
	}
	go w.run(wctx)
	return wctx, func() { cancel(context.Canceled) }
}

type watcher struct {
	x      *Sessions
	sid    string
	o      WatchOptions
	cancel context.CancelCauseFunc
	once   sync.Once
	// learned from qAuth (nanoseconds)
	poll, heartbeat atomic.Int64
}

func (w *watcher) end(cause error) {
	w.once.Do(func() {
		var e *SessionEndedError
		if errors.As(cause, &e) && w.o.OnEnded != nil {
			w.o.OnEnded(e.Reason)
		}
		w.cancel(cause)
	})
}

func (w *watcher) pollEvery() time.Duration {
	switch {
	case w.o.PollInterval > 0:
		return w.o.PollInterval
	case w.poll.Load() > 0:
		return time.Duration(w.poll.Load())
	}
	return 45 * time.Second
}

func (w *watcher) run(ctx context.Context) {
	failures := 0
	for ctx.Err() == nil {
		ready, wait, err := w.stream(ctx)
		if err != nil {
			w.end(err)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if ready {
			failures = 0
		}
		if wait < 0 { // qAuth said reconnect: at once
			continue
		}
		failures++
		backoff := min(w.o.MaxBackoff, time.Second<<min(failures-1, 16))
		backoff = time.Duration(float64(backoff) * (0.8 + 0.4*rand.Float64()))
		w.downFor(ctx, max(wait, backoff))
	}
}

// downFor waits d while the stream is down, asking for the state every
// poll interval meanwhile.
func (w *watcher) downFor(ctx context.Context, d time.Duration) {
	until := time.Now().Add(d)
	for ctx.Err() == nil {
		if w.check(ctx) {
			return
		}
		left := time.Until(until)
		if left <= 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(min(left, w.pollEvery())):
		}
		if time.Now().After(until) {
			return
		}
	}
}

// check asks for the session's state; true when the watch ended.
func (w *watcher) check(ctx context.Context) bool {
	st, err := w.x.State(ctx, w.sid, w.o.ClientID)
	if StatusOf(err) == http.StatusUnauthorized {
		w.end(ErrTokenRefused)
		return true
	}
	if err != nil {
		return false // offline: the next try asks again
	}
	if st.PollSeconds > 0 {
		w.poll.Store(int64(time.Duration(st.PollSeconds) * time.Second))
	}
	if st.Ended != "" {
		w.end(&SessionEndedError{Reason: st.Ended})
		return true
	}
	return false
}

// stream holds one stream open. ready: it was up; wait: how long to wait
// before the next one (-1 = at once); err: the watch is over.
func (w *watcher) stream(ctx context.Context) (ready bool, wait time.Duration, err error) {
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	q := url.Values{}
	if w.o.ClientID != "" {
		q.Set("client", w.o.ClientID)
	}
	u := w.x.t.c.base + "/v1/me/sessions/" + seg(w.sid) + "/events"
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, rerr := http.NewRequestWithContext(sctx, http.MethodGet, u, nil)
	if rerr != nil {
		return false, 0, rerr
	}
	for k, v := range w.x.t.header {
		req.Header[k] = v
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "qauth-go/"+Version)
	// a stream outlives the client's request timeout
	hc := *w.x.t.c.hc
	hc.Timeout = 0
	res, derr := hc.Do(req)
	if derr != nil {
		return false, 0, nil
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return false, 0, ErrTokenRefused
	case res.StatusCode == http.StatusTooManyRequests:
		// too many streams: poll instead for a while
		ra, _ := strconv.Atoi(res.Header.Get("Retry-After"))
		return false, max(w.pollEvery(), time.Duration(ra)*time.Second), nil
	case res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream"):
		return false, 0, nil
	}
	// no byte for three heartbeats: the stream is dead (a proxy dropped it)
	beat := make(chan struct{}, 1)
	go func() {
		hb := 25 * time.Second
		for {
			if v := w.heartbeat.Load(); v > 0 {
				hb = time.Duration(v)
			}
			select {
			case <-sctx.Done():
				return
			case <-beat:
			case <-time.After(3 * hb):
				stop()
				return
			}
		}
	}()
	sc := bufio.NewScanner(res.Body)
	name, data := "message", ""
	for sc.Scan() {
		select {
		case beat <- struct{}{}:
		default:
		}
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			name = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "data:"):
			data = strings.TrimSpace(line[5:])
		case line == "":
			var d struct {
				Reason           string `json:"reason"`
				PollSeconds      int    `json:"pollSeconds"`
				HeartbeatSeconds int    `json:"heartbeatSeconds"`
			}
			_ = json.Unmarshal([]byte(data), &d)
			switch name {
			case "ready":
				ready = true
				if d.PollSeconds > 0 {
					w.poll.Store(int64(time.Duration(d.PollSeconds) * time.Second))
				}
				if d.HeartbeatSeconds > 0 {
					w.heartbeat.Store(int64(time.Duration(d.HeartbeatSeconds) * time.Second))
				}
			case "ended":
				if d.Reason == "" {
					d.Reason = "signed_out"
				}
				return ready, 0, &SessionEndedError{Reason: d.Reason}
			case "reconnect":
				return ready, -1, nil
			}
			name, data = "message", ""
		}
	}
	return ready, 0, nil // closed under us (or dead): reconnect after a short wait
}
