package qauth

import (
	"strings"
	"unicode"
)

// Browser is the person's browser, for calls your server makes on their
// behalf (EXA-640). Both fields are optional.
//
// UserAgent and IP are the person's browser (its User-Agent header and its
// address, not your server's). The passkey routes use them for the new
// passkey's name, the "a passkey was added" email and the audit (marked as
// app-supplied), and to keep the code and lockout counts of people behind
// your server apart. They never grant access. An IP that doesn't parse is
// ignored.
type Browser struct {
	UserAgent string
	IP        string
}

// Header names Browser is sent in.
const (
	HeaderClientUA = "X-QAuth-Client-UA"
	HeaderClientIP = "X-QAuth-Client-IP"
)

// AsBrowser is As, with the person's browser sent on every call (see
// Browser). Which sign-in a token belongs to needs nothing from you: qAuth
// ties every access token to its sign-in when it issues it.
func (c *Client) AsBrowser(accessToken string, b Browser) *Person {
	p := newPerson(c, accessToken)
	h := p.t.header
	for k, v := range map[string]string{HeaderClientUA: b.UserAgent, HeaderClientIP: b.IP} {
		if v = headerSafe(v); v != "" {
			h.Set(k, v)
		}
	}
	return p
}

// headerSafe drops control characters (a header value can't hold them) and
// keeps the first 512 bytes.
func headerSafe(v string) string {
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, v)
	for len(v) > 512 {
		_, n := lastRune(v)
		v = v[:len(v)-n]
	}
	return strings.TrimSpace(v)
}

func lastRune(s string) (rune, int) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i]&0xC0 != 0x80 {
			return rune(s[i]), len(s) - i
		}
	}
	return 0, len(s)
}
