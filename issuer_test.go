package qauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// fakeAPI is qAuth's API: it records each call (path + credential).
func fakeAPI(t *testing.T) (*httptest.Server, func() []string) {
	var mu sync.Mutex
	calls := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.URL.Path+" "+r.Header.Get("Authorization")+r.Header.Get("X-Api-Key"))
		mu.Unlock()
		var data any = map[string]any{"id": "o1", "name": "Shop"}
		if strings.HasSuffix(r.URL.Path, "/orgs") {
			data = []any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "status": 200, "data": data})
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string{}, calls...) }
}

// FromIssuer: qAuth's API address from discovery (qauth_api), a Verifier for
// that issuer and client wired in, and the API key for Org.
func TestFromIssuer(t *testing.T) {
	f := newFakeIssuer(t)
	k := newKey(t, "k1", jose.RS256)
	f.publish(k)
	api, calls := fakeAPI(t)
	f.set(func(f *fakeIssuer) { f.extra = map[string]any{"qauth_api": api.URL + "/"} })
	ctx := context.Background()
	apiHost := strings.TrimPrefix(api.URL, "http://")
	c, err := FromIssuer(ctx, f.srv.URL, "web-client", WithAPIKey("qak_test"), WithTrustedAPIHosts(apiHost))
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != api.URL || c.Verifier() == nil {
		t.Fatalf("base %q verifier %v", c.BaseURL(), c.Verifier())
	}
	now := time.Now()
	claims := claimsFor(f, map[string]any{"exp": now.Add(15 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix()})
	tok := sign(t, k, claims)
	id, err := c.Verifier().Verify(ctx, tok)
	if err != nil || id.Subject != "user-1" || id.Issuer != f.srv.URL {
		t.Fatalf("verify: %+v %v", id, err)
	}
	claims["client_id"] = "other-client"
	if _, err := c.Verifier().Verify(ctx, sign(t, k, claims)); StatusOf(err) != http.StatusUnauthorized {
		t.Fatalf("another client's token: %v", err)
	}
	if _, err := c.Org("o1").Get(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.As(tok).Orgs(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls(), ";"); got != "/v1/orgs/o1 qak_test;/v1/me/orgs Bearer "+tok {
		t.Fatalf("calls: %s", got)
	}
	// permissions are cached per person: the verifier is wired by default
	if c.verifier == nil {
		t.Fatal("no verifier wired")
	}
	// your own verifier wins
	mine, _ := NewVerifier(VerifierConfig{Issuers: []string{f.srv.URL}, ClientIDs: []string{"x"}})
	if c2, err := FromIssuer(ctx, f.srv.URL, "web-client", WithVerifier(mine), WithTrustedAPIHosts(apiHost)); err != nil || c2.Verifier() != mine {
		t.Fatalf("own verifier: %v", err)
	}
	// New still works as before
	if c3, err := New(api.URL); err != nil || c3.Verifier() != nil {
		t.Fatalf("New: %v", err)
	}
}

// Refused: an issuer or qauth_api that isn't https (localhost allowed), a
// redirect, another issuer in discovery, no qauth_api.
func TestFromIssuerRefusals(t *testing.T) {
	ctx := context.Background()
	if _, err := FromIssuer(ctx, "http://acme.qapps.dev", "web"); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http issuer: %v", err)
	}
	if _, err := FromIssuer(ctx, "https://acme.qapps.dev", ""); err == nil {
		t.Fatal("no client id")
	}
	for name, tc := range map[string]struct {
		mod  func(f *fakeIssuer)
		want string
	}{
		"http api": {func(f *fakeIssuer) { f.extra = map[string]any{"qauth_api": "http://auth.qapps.dev"} }, "API the issuer names is not an https"},
		"no api":   {func(f *fakeIssuer) {}, "names no qAuth API"},
		"another issuer": {func(f *fakeIssuer) {
			f.discIss = "https://evil.test"
			f.extra = map[string]any{"qauth_api": "https://auth.qapps.dev"}
		}, "names another issuer"},
		"redirect":      {func(f *fakeIssuer) { f.redirect = "https://evil.test/.well-known/openid-configuration" }, "redirect"},
		"untrusted api": {func(f *fakeIssuer) { f.extra = map[string]any{"qauth_api": "https://auth.evil.test"} }, "isn't a known qAuth address"},
		"down":          {func(f *fakeIssuer) { f.down = true }, "HTTP 502"},
	} {
		f := newFakeIssuer(t)
		f.set(tc.mod)
		c, err := FromIssuer(ctx, f.srv.URL, "web")
		if err == nil || c != nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// qAuth's own address is trusted by default
	f := newFakeIssuer(t)
	f.set(func(f *fakeIssuer) { f.extra = map[string]any{"qauth_api": "https://auth.qapps.dev"} })
	if c, err := FromIssuer(ctx, f.srv.URL, "web"); err != nil || c.BaseURL() != "https://auth.qapps.dev" {
		t.Fatalf("default trusted host: %v", err)
	}
	// a qauth_api on this machine is allowed (local development), once trusted
	f.set(func(f *fakeIssuer) { f.extra = map[string]any{"qauth_api": "http://localhost:8080"} })
	if _, err := FromIssuer(ctx, f.srv.URL, "web"); err == nil {
		t.Fatal("an untrusted localhost API accepted")
	}
	if c, err := FromIssuer(ctx, f.srv.URL, "web", WithTrustedAPIHosts("localhost:8080")); err != nil || c.BaseURL() != "http://localhost:8080" {
		t.Fatalf("localhost: %v", err)
	}
	// a caller's client that follows redirects still never follows one here
	r := newFakeIssuer(t)
	target := newFakeIssuer(t)
	target.set(func(x *fakeIssuer) {
		x.discIss = r.srv.URL
		x.extra = map[string]any{"qauth_api": "https://auth.qapps.dev"}
	})
	r.set(func(x *fakeIssuer) { x.redirect = target.srv.URL + "/.well-known/openid-configuration" })
	follows := &http.Client{}
	if _, err := FromIssuer(ctx, r.srv.URL, "web", WithHTTPClient(follows)); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect followed with the caller's client: %v", err)
	}
	if follows.CheckRedirect != nil {
		t.Fatal("the caller's client was changed")
	}
}
