package qauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func serve(t *testing.T, v *Verifier, auth string) (*httptest.ResponseRecorder, *Identity) {
	t.Helper()
	var seen *Identity
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := IdentityFrom(r.Context())
		if !ok {
			t.Fatal("handler ran without an identity")
		}
		seen = id
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/things", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, seen
}

func errBody(t *testing.T, rec *httptest.ResponseRecorder) (code string) {
	t.Helper()
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Error   struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil || env.Success || env.Message != env.Error.Code {
		t.Fatalf("body %s", rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cache-control")
	}
	return env.Error.Code
}

func TestMiddlewareLetsAValidTokenThrough(t *testing.T) {
	v, f, k, _ := setup(t)
	tok := sign(t, k, claimsFor(f, nil))
	for _, scheme := range []string{"Bearer ", "bearer "} {
		rec, id := serve(t, v, scheme+tok)
		if rec.Code != http.StatusNoContent || id == nil || id.Subject != "user-1" {
			t.Fatalf("%q: %d %+v", scheme, rec.Code, id)
		}
	}
}

func TestMiddlewareNoToken(t *testing.T) {
	v, _, _, _ := setup(t)
	for _, auth := range []string{"", "Basic dXNlcjpwYXNz", "Bearer "} {
		rec, _ := serve(t, v, auth)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%q: %d", auth, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="api"` {
			t.Fatalf("%q: WWW-Authenticate %q", auth, got)
		}
		if c := errBody(t, rec); c != CodeTokenMissing {
			t.Fatalf("code %s", c)
		}
	}
}

func TestMiddlewareRefusedToken(t *testing.T) {
	v, f, k, _ := setup(t)
	rec, _ := serve(t, v, "Bearer "+sign(t, k, claimsFor(f, map[string]any{"client_id": "nope"})))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("%d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="api", error="invalid_token", error_description="WRONG_CLIENT"` {
		t.Fatalf("WWW-Authenticate %q", got)
	}
	if c := errBody(t, rec); c != CodeWrongClient {
		t.Fatalf("code %s", c)
	}
}

func TestMiddlewareIssuerDownIs503(t *testing.T) {
	v, f, k, _ := setup(t)
	f.set(func(f *fakeIssuer) { f.down = true })
	rec, _ := serve(t, v, "Bearer "+sign(t, k, claimsFor(f, nil)))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	if c := errBody(t, rec); c != CodeKeysUnavailable {
		t.Fatalf("code %s", c)
	}
}

func TestIdentityFromEmptyContext(t *testing.T) {
	if _, ok := IdentityFrom(httptest.NewRequest("GET", "/", nil).Context()); ok {
		t.Fatal("identity from nowhere")
	}
	ctx := ContextWithIdentity(t.Context(), &Identity{Subject: "s"})
	if id, ok := IdentityFrom(ctx); !ok || id.Subject != "s" {
		t.Fatal("round trip")
	}
}

func TestOptionalMiddleware(t *testing.T) {
	v, f, k, _ := setup(t)
	var saw []bool
	h := v.OptionalMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := IdentityFrom(r.Context())
		saw = append(saw, ok)
	}))
	for _, auth := range []string{"", "Bearer " + sign(t, k, claimsFor(f, nil))} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if len(saw) != 2 || saw[0] || !saw[1] {
		t.Fatal(saw)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer junk")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || len(saw) != 2 {
		t.Fatal("a bad token passed the optional middleware")
	}
}
