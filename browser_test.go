package qauth

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// AsBrowser sends the browser's details on every call;
// As sends none; control characters never reach a header.
func TestAsBrowserSendsTheHeaders(t *testing.T) {
	var got http.Header
	f := newFakeQAuth(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		ok(w, map[string]any{"ceremony": "c1", "rpId": "id.a.test", "expiresAt": "2026-11-28T00:00:00Z"})
	})
	c, _ := newTestClient(t, f.srv.URL)
	ctx := context.Background()
	p := c.AsBrowser("tok", Browser{UserAgent: "Mozilla/5.0\r\nX-Evil: 1", IP: "203.0.113.7"})
	if _, err := p.Account.Passkeys().Begin(ctx, "https://app.test", false); err != nil {
		t.Fatal(err)
	}
	if got.Get(HeaderClientIP) != "203.0.113.7" || got.Get("Authorization") != "Bearer tok" {
		t.Fatalf("headers: %v", got)
	}
	if ua := got.Get(HeaderClientUA); ua != "Mozilla/5.0X-Evil: 1" || got.Get("X-Evil") != "" {
		t.Fatalf("user agent: %q", ua)
	}
	if _, err := c.AsBrowser("tok", Browser{IP: "203.0.113.8"}).Account.Security(ctx); err != nil && !strings.Contains(err.Error(), "shape") {
		t.Fatal(err)
	}
	if got.Get(HeaderClientIP) != "203.0.113.8" || got.Get(HeaderClientUA) != "" {
		t.Fatalf("address only: %v", got)
	}
	_, _ = c.As("tok").Account.Security(ctx)
	if got.Get(HeaderClientUA) != "" || got.Get(HeaderClientIP) != "" || got.Get("X-QAuth-Session") != "" {
		t.Fatalf("As sent browser headers: %v", got)
	}
	if long := headerSafe(strings.Repeat("é", 400)); len(long) > 512 || !strings.HasPrefix(long, "é") {
		t.Fatalf("cap: %d", len(long))
	}
}
