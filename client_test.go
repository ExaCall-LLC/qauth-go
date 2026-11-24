package qauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeQAuth answers in qAuth's envelope and counts calls per path.
type fakeQAuth struct {
	srv   *httptest.Server
	hits  map[string]*atomic.Int32
	reply func(w http.ResponseWriter, r *http.Request)
}

func newFakeQAuth(t *testing.T, reply func(w http.ResponseWriter, r *http.Request)) *fakeQAuth {
	f := &fakeQAuth{hits: map[string]*atomic.Int32{"/v1/me/permissions": {}, "/auth/validate": {}}, reply: reply}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := f.hits[r.URL.Path]; h != nil {
			h.Add(1)
		}
		f.reply(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func ok(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "status": 200, "message": "OK", "data": data, "meta": map[string]any{"request_id": "req_1"}})
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "status": status, "message": msg, "data": nil,
		"error": map[string]any{"code": code, "message": msg}, "meta": map[string]any{"request_id": "req_2"}})
}

// permsByToken answers permissions per bearer token (whatever the token says).
func permsByToken(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get("Authorization") {
	case "Bearer token-a":
		ok(w, map[string]any{"app": r.URL.Query().Get("app"), "org": r.URL.Query().Get("org"), "roles": []string{"r"}, "permissions": []string{"contacts:read"}, "orgPermissions": []string{}})
	case "Bearer token-b":
		ok(w, map[string]any{"app": "a", "org": "o", "roles": []string{}, "permissions": []string{}, "orgPermissions": []string{}})
	case "Bearer outsider":
		fail(w, 404, CodeNotFound, "not found")
	case "Bearer busy":
		w.Header().Set("Retry-After", "7")
		fail(w, 429, CodeRateLimited, "slow down")
	default:
		fail(w, 401, CodeUnauthorized, "The token is invalid or expired.")
	}
}

func newTestClient(t *testing.T, base string, opts ...Option) (*Client, *clock) {
	t.Helper()
	c, err := New(base, opts...)
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: t0}
	c.now = clk.now
	return c, clk
}

func TestPermissionsCache(t *testing.T) {
	ctx := context.Background()
	f := newFakeQAuth(t, permsByToken)
	c, clk := newTestClient(t, f.srv.URL)
	hits := f.hits["/v1/me/permissions"]
	for range 3 {
		yes, err := c.Can(ctx, Token("token-a"), "app1", "org1", "contacts:read")
		if err != nil || !yes {
			t.Fatal(yes, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d, want 1 (cached)", hits.Load())
	}
	// another org is another entry
	_, _ = c.Can(ctx, Token("token-a"), "app1", "org2", "contacts:read")
	if hits.Load() != 2 {
		t.Fatalf("hits %d", hits.Load())
	}
	clk.add(61 * time.Second)
	_, _ = c.Can(ctx, Token("token-a"), "app1", "org1", "contacts:read")
	if hits.Load() != 3 {
		t.Fatalf("hits %d, want 3 (expired)", hits.Load())
	}
}

func TestPermissionsCacheOff(t *testing.T) {
	f := newFakeQAuth(t, permsByToken)
	c, _ := newTestClient(t, f.srv.URL, WithPermissionsCache(0))
	for range 3 {
		_, _ = c.Permissions(context.Background(), Token("token-a"), "app1", "org1")
	}
	if n := f.hits["/v1/me/permissions"].Load(); n != 3 {
		t.Fatalf("hits %d, want 3", n)
	}
}

// The cache is keyed by the token itself, never by a sub read from an
// unverified token: two tokens naming the same person never share answers.
func TestPermissionsCacheKeyIsTheToken(t *testing.T) {
	ctx := context.Background()
	f := newFakeQAuth(t, permsByToken)
	c, _ := newTestClient(t, f.srv.URL)
	if yes, _ := c.Can(ctx, Token("token-a"), "a", "o", "contacts:read"); !yes {
		t.Fatal("token-a")
	}
	if yes, _ := c.Can(ctx, Token("token-b"), "a", "o", "contacts:read"); yes {
		t.Fatal("token-b got token-a's cached permissions")
	}
	// an unverified JWT naming someone's sub is just another token
	forged := handMade(map[string]any{"alg": "none"}, map[string]any{"sub": "victim"}, nil)
	_, err := c.Can(ctx, Token(forged), "a", "o", "contacts:read")
	wantCode(t, err, ErrUnauthorized, 401)
}

func TestCanOutsiderAndErrors(t *testing.T) {
	ctx := context.Background()
	f := newFakeQAuth(t, permsByToken)
	c, _ := newTestClient(t, f.srv.URL)
	if yes, err := c.Can(ctx, Token("outsider"), "a", "o", "x"); yes || err != nil {
		t.Fatalf("outsider: %v %v", yes, err)
	}
	_, err := c.Can(ctx, Token("bad"), "a", "o", "x")
	wantCode(t, err, ErrUnauthorized, 401)
	var e *Error
	if !errors.As(err, &e) || e.RequestID != "req_2" || e.Message == "" {
		t.Fatalf("%+v", e)
	}
	// rate limited: an error with Retry-After, and never cached
	for range 2 {
		_, err = c.Can(ctx, Token("busy"), "a", "o", "x")
		wantCode(t, err, ErrRateLimited, 429)
		if !errors.As(err, &e) || e.RetryAfter != 7*time.Second {
			t.Fatalf("retry after %v", e.RetryAfter)
		}
	}
	if n := f.hits["/v1/me/permissions"].Load(); n != 4 {
		t.Fatalf("hits %d (errors must not be cached)", n)
	}
}

func keysReply(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get("X-Api-Key") {
	case "qak_good":
		if app := r.Header.Get("X-Qauth-App"); app != "" && app != "app1" {
			fail(w, 401, CodeUnauthorized, "not valid")
			return
		}
		ok(w, map[string]any{"valid": true, "key": map[string]any{"id": "k1", "name": "Sync", "tenantId": "t", "orgId": "o",
			"kind": "m2m", "owner": map[string]any{"type": "organization", "id": "o"}, "scopes": []string{}, "apps": []string{"app1"},
			"permissions": map[string][]string{"api1": {"contacts:read"}}, "expiresAt": nil}})
	case "qak_busy":
		// the test clock is t0+31s by then: 5 s to wait
		w.Header().Set("Retry-After", t0.Add(36*time.Second).UTC().Format(http.TimeFormat))
		fail(w, 429, CodeRateLimited, "slow down")
	default:
		fail(w, 401, CodeUnauthorized, "not valid")
	}
}

func TestValidateKeyAndCache(t *testing.T) {
	ctx := context.Background()
	f := newFakeQAuth(t, keysReply)
	c, clk := newTestClient(t, f.srv.URL, WithKeyCache(30*time.Second))
	hits := f.hits["/auth/validate"]
	for range 2 {
		kc, err := c.ValidateKey(ctx, "qak_good", ValidateKeyOptions{App: "app1"})
		if err != nil || !kc.Valid || kc.Key.Owner.Type != "organization" || kc.Key.ExpiresAt != nil {
			t.Fatalf("%v %+v", err, kc)
		}
		if !KeyMay(kc, "api1", "contacts:read") || KeyMay(kc, "api1", "contacts:write") || KeyMay(kc, "api2", "contacts:read") {
			t.Fatal("KeyMay")
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d, want 1", hits.Load())
	}
	// another app is another entry, and not valid
	kc, err := c.ValidateKey(ctx, "qak_good", ValidateKeyOptions{App: "app2"})
	if err != nil || kc.Valid || KeyMay(kc, "api1", "contacts:read") {
		t.Fatalf("%v %+v", err, kc)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits %d", hits.Load())
	}
	clk.add(31 * time.Second)
	_, _ = c.ValidateKey(ctx, "qak_good", ValidateKeyOptions{App: "app1"})
	if hits.Load() != 3 {
		t.Fatalf("hits %d, want 3 (expired)", hits.Load())
	}
	// unknown key: not valid, no error
	if kc, err := c.ValidateKey(ctx, "qak_unknown", ValidateKeyOptions{}); err != nil || kc.Valid {
		t.Fatalf("%v %+v", err, kc)
	}
	// rate limited: error (an HTTP-date Retry-After), not cached
	for range 2 {
		_, err = c.ValidateKey(ctx, "qak_busy", ValidateKeyOptions{})
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeRateLimited || e.RetryAfter <= 0 || e.RetryAfter > 6*time.Second {
			t.Fatalf("%v %v", err, e.RetryAfter)
		}
	}
	if hits.Load() != 6 {
		t.Fatalf("hits %d", hits.Load())
	}
	// cache off by default: a revoked key stops at once
	off, _ := newTestClient(t, f.srv.URL)
	_, _ = off.ValidateKey(ctx, "qak_good", ValidateKeyOptions{})
	_, _ = off.ValidateKey(ctx, "qak_good", ValidateKeyOptions{})
	if hits.Load() != 8 {
		t.Fatalf("hits %d, want 8 (no cache)", hits.Load())
	}
}

func TestTransportErrors(t *testing.T) {
	ctx := context.Background()
	f := newFakeQAuth(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/me":
			w.WriteHeader(502)
			_, _ = w.Write([]byte("<html>bad gateway</html>"))
		case "/v1/me/orgs":
			fail(w, 422, CodeValidation, "fix it")
		}
	})
	c, _ := newTestClient(t, f.srv.URL)
	_, err := c.As("t").Profile(ctx)
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeBadResponse || e.Status != 502 {
		t.Fatalf("%v", err)
	}
	_, err = c.Orgs(ctx, Token("t"))
	wantCode(t, err, ErrValidation, 422)

	dead, _ := newTestClient(t, "http://127.0.0.1:1")
	_, err = dead.As("t").Profile(ctx)
	if !errors.As(err, &e) || e.Code != CodeUnavailable || e.Status != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if _, err := New("ftp://x"); err == nil {
		t.Fatal("ftp accepted")
	}
}

func TestCacheBounded(t *testing.T) {
	clk := &clock{t: t0}
	c := newTTLCache[int](time.Minute, 3, clk.now)
	for i := range 10 {
		_, _ = c.load(context.Background(), string(rune('a'+i)), func() (int, error) { return i, nil }, nil)
	}
	if c.size() > 3 {
		t.Fatalf("%d entries", c.size())
	}
	if v, _ := c.load(context.Background(), "j", func() (int, error) { return -1, nil }, nil); v != 9 {
		t.Fatal("latest entry lost")
	}
}

// Concurrent asks share one request, even with the cache off.
func TestPermissionsConcurrentShareOneCall(t *testing.T) {
	release := make(chan struct{})
	f := newFakeQAuth(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		permsByToken(w, r)
	})
	c, _ := newTestClient(t, f.srv.URL, WithPermissionsCache(0))
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if yes, err := c.Can(context.Background(), Token("token-a"), "a", "o", "contacts:read"); !yes || err != nil {
				t.Error(yes, err)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond) // let them all ask
	close(release)
	wg.Wait()
	if n := f.hits["/v1/me/permissions"].Load(); n != 1 {
		t.Fatalf("hits %d, want 1", n)
	}
	// and nothing kept afterwards
	_, _ = c.Can(context.Background(), Token("token-a"), "a", "o", "contacts:read")
	if n := f.hits["/v1/me/permissions"].Load(); n != 2 {
		t.Fatalf("hits %d, want 2", n)
	}
}

// With a Verifier, a raw token is verified offline first and answers are
// kept per person (issuer + sub): a refused token never reaches qAuth.
func TestPermissionsPerVerifiedPerson(t *testing.T) {
	ctx := context.Background()
	v, iss, k, _ := setup(t)
	v.now = time.Now
	f := newFakeQAuth(t, func(w http.ResponseWriter, r *http.Request) {
		ok(w, map[string]any{"app": "a", "org": "o", "roles": []string{}, "permissions": []string{"contacts:read"}, "orgPermissions": []string{}})
	})
	c, _ := newTestClient(t, f.srv.URL, WithVerifier(v))
	hits := f.hits["/v1/me/permissions"]
	now := time.Now()
	fresh := func(jti string) string {
		return sign(t, k, claimsFor(iss, map[string]any{"jti": jti, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix()}))
	}
	if yes, err := c.Can(ctx, Token(fresh("one")), "a", "o", "contacts:read"); !yes || err != nil {
		t.Fatal(yes, err)
	}
	// a second token of the same person: the kept answer
	id, err := v.Verify(ctx, fresh("two"))
	if err != nil {
		t.Fatal(err)
	}
	if yes, _ := c.Can(ctx, id, "a", "o", "contacts:read"); !yes || hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
	// an unverified token naming the same sub is refused offline
	forged := handMade(map[string]any{"alg": "none"}, claimsFor(iss, nil), nil)
	_, err = c.Can(ctx, Token(forged), "a", "o", "contacts:read")
	wantCode(t, err, ErrBadSignature, 401)
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
	// Forget drops the person's answers
	c.Forget(ctx, id)
	_, _ = c.Can(ctx, id, "a", "o", "contacts:read")
	if hits.Load() != 2 {
		t.Fatalf("hits %d, want 2 after Forget", hits.Load())
	}
}

func TestRequestIDFromHeader(t *testing.T) {
	f := newFakeQAuth(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "req_hdr")
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"success":false,"status":403,"message":"no","error":{"code":"FORBIDDEN","message":"no"}}`))
	})
	c, _ := newTestClient(t, f.srv.URL)
	_, err := c.As("t").Profile(context.Background())
	var e *Error
	if !errors.As(err, &e) || e.RequestID != "req_hdr" || e.Code != CodeForbidden {
		t.Fatalf("%+v", e)
	}
}

func TestIsFreshStepUp(t *testing.T) {
	sent := time.Now().Add(-time.Minute)
	if !IsFreshStepUp(&StepUp{At: time.Now(), Method: "authenticator"}, sent, 0) {
		t.Fatal("fresh")
	}
	if IsFreshStepUp(&StepUp{At: time.Now().Add(-2 * time.Minute)}, sent, 0) {
		t.Fatal("before you sent them")
	}
	if IsFreshStepUp(nil, sent, 0) {
		t.Fatal("nil")
	}
	if IsFreshStepUp(&StepUp{At: sent.Add(time.Second)}, sent.Add(-time.Hour), time.Second) {
		t.Fatal("outside the window")
	}
}

// Answers handed out are copies: changing one never changes the kept answer.
func TestCachedAnswersAreCopies(t *testing.T) {
	ctx := context.Background()
	f := newFakeQAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/validate" {
			keysReply(w, r)
			return
		}
		permsByToken(w, r)
	})
	c, _ := newTestClient(t, f.srv.URL, WithKeyCache(time.Minute))
	e, _ := c.Permissions(ctx, Token("token-a"), "a", "o")
	e.Permissions[0] = "admin:everything"
	if yes, _ := c.Can(ctx, Token("token-a"), "a", "o", "admin:everything"); yes {
		t.Fatal("a caller changed the kept permissions")
	}
	kc, _ := c.ValidateKey(ctx, "qak_good", ValidateKeyOptions{})
	kc.Key.Permissions["api1"] = append(kc.Key.Permissions["api1"], "contacts:write")
	if again, _ := c.ValidateKey(ctx, "qak_good", ValidateKeyOptions{}); KeyMay(again, "api1", "contacts:write") {
		t.Fatal("a caller changed the kept key check")
	}
	if f.hits["/v1/me/permissions"].Load() != 1 || f.hits["/auth/validate"].Load() != 1 {
		t.Fatal("not served from the cache")
	}
}

// A caller waiting on another's call stops when its own context ends.
func TestWaiterHonoursItsContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	f := newFakeQAuth(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		permsByToken(w, r)
	})
	c, _ := newTestClient(t, f.srv.URL)
	go func() { _, _ = c.Permissions(context.Background(), Token("token-a"), "a", "o") }()
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.Permissions(ctx, Token("token-a"), "a", "o")
	wantCode(t, err, ErrUnavailable, 0)
}

// qAuth's client never follows a redirect: the token and API key never
// reach another address.
func TestClientNoRedirects(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "" || r.Header.Get("Authorization") != "" {
			leaked.Add(1)
		}
		ok(w, map[string]any{"valid": true})
	}))
	t.Cleanup(target.Close)
	f := newFakeQAuth(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	c, _ := newTestClient(t, f.srv.URL)
	_, err := c.ValidateKey(context.Background(), "qak_secret", ValidateKeyOptions{})
	wantCode(t, err, ErrUnexpectedRedirect, 307)
	_, err = c.As("tok").Profile(context.Background())
	wantCode(t, err, ErrUnexpectedRedirect, 307)
	if leaked.Load() != 0 {
		t.Fatal("a credential followed the redirect")
	}
}

// An empty, "." or ".." id is refused before anything is sent.
func TestClientRefusesBadIDs(t *testing.T) {
	var hits atomic.Int32
	f := newFakeQAuth(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); ok(w, nil) })
	c, _ := newTestClient(t, f.srv.URL)
	ctx := context.Background()
	for _, id := range []string{"", ".", ".."} {
		if err := c.As("t").Org("org1").Members.Remove(ctx, id); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%q: %v", id, err)
		}
		if _, err := c.As("t").Org(id).Get(ctx); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("org %q: %v", id, err)
		}
	}
	if err := c.As("t").Tokens.Revoke(ctx, "a/../../admin"); err == nil && hits.Load() == 0 {
		t.Fatal("not sent at all") // escaped into one segment: allowed, harmless
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d, want 1", hits.Load())
	}
}

func TestNewRefusesPlainHTTP(t *testing.T) {
	for _, u := range []string{"http://auth.qapps.dev", "ftp://x", "auth.qapps.dev"} {
		if _, err := New(u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	for _, u := range []string{"https://auth.qapps.dev", "http://127.0.0.1:8080", "http://localhost:1", "http://[::1]:2"} {
		if _, err := New(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}
