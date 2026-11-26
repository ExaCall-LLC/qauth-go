package qauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Client calls qAuth's API (e.g. https://auth.qapps.dev): as a person with
// their access token (As), as an organization's API key (WithKey), to ask
// what a person may do (Permissions, Can, Orgs) and to check API keys
// (ValidateKey). It is safe for concurrent use; create one and share it.
//
// Never call qAuth from a browser with these calls: tokens and API keys stay
// on your server.
type Client struct {
	base      string
	hc        *http.Client
	timeout   time.Duration
	permTTL   time.Duration
	keyTTL    time.Duration
	cacheSize int
	verifier  *Verifier
	apiKey    string
	// trustedAPI: the qAuth API hosts FromIssuer accepts (nil = default)
	trustedAPI []string
	now        func() time.Time

	perms *ttlCache[*Effective]
	orgs  *ttlCache[[]MyOrg]
	keys  *ttlCache[KeyCheck]
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client (proxies, tests). Default: a client
// that never follows redirects. Your own must not follow them either
// (CheckRedirect returning http.ErrUseLastResponse): a redirect could carry
// the person's token or an API key elsewhere. Give it a timeout too.
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.hc = hc } }

// WithTimeout sets the per-request timeout. Default 15 seconds.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }

// WithPermissionsCache sets how long Permissions, Can and Orgs keep an
// answer, per person, app and organization. Default 60 seconds; 0 means
// always ask qAuth.
func WithPermissionsCache(ttl time.Duration) Option { return func(c *Client) { c.permTTL = ttl } }

// WithKeyCache sets how long ValidateKey keeps an answer (valid or not),
// keyed on a hash of the key. Default 0: every check asks qAuth, so a
// revoked key stops at once. 30 seconds is a good value for busy APIs (a
// revoked key then works for up to 30 s more).
func WithKeyCache(ttl time.Duration) Option { return func(c *Client) { c.keyTTL = ttl } }

// WithVerifier makes Permissions, Can and Orgs verify a raw Token offline
// first and cache per person (issuer and sub). Without it, a raw token's
// answers are cached per token.
func WithVerifier(v *Verifier) Option { return func(c *Client) { c.verifier = v } }

// WithCacheSize caps the entries of each cache. Default 10000.
func WithCacheSize(n int) Option { return func(c *Client) { c.cacheSize = n } }

// New returns a Client for qAuth's API at baseURL.
func New(baseURL string, opts ...Option) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || !secureURL(u.String()) {
		return nil, fmt.Errorf("qauth: baseURL %q is not an https address (http only for localhost)", baseURL)
	}
	c := &Client{base: u.String(), timeout: 15 * time.Second, permTTL: 60 * time.Second, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	if c.hc == nil {
		c.hc = &http.Client{CheckRedirect: noRedirect}
	}
	clock := func() time.Time { return c.now() }
	c.perms = newTTLCache[*Effective](c.permTTL, c.cacheSize, clock)
	c.orgs = newTTLCache[[]MyOrg](c.permTTL, c.cacheSize, clock)
	c.keys = newTTLCache[KeyCheck](c.keyTTL, c.cacheSize, clock)
	return c, nil
}

// As acts as the signed-in person, with their access token.
func (c *Client) As(accessToken string) *Person {
	return newPerson(c, accessToken)
}

// KeyClient acts as an organization's API key (qak_...).
type KeyClient struct{ t *transport }

// WithKey acts as an organization's API key on its own organization, within
// its qauth:org:* scopes. It can never change settings, security, company
// sign-in, keys or the admin role.
func (c *Client) WithKey(apiKey string) *KeyClient {
	return &KeyClient{t: &transport{c: c, header: http.Header{"X-Api-Key": {apiKey}}}}
}

// Org is the key's organization.
func (k *KeyClient) Org(orgID string) *OrgClient { return newOrgClient(k.t, orgID) }

// Who is the person a permissions question is about: a verified *Identity
// (from Verifier.Verify or IdentityFrom), or their raw access Token.
type Who interface{ isWho() }

// Token is a person's raw access token, as a Who.
type Token string

func (Token) isWho()     {}
func (*Identity) isWho() {}

// whoKey answers the token to call qAuth with and the cache key prefix:
// issuer and sub for a verified person, else a hash of the token.
func (c *Client) whoKey(ctx context.Context, who Who) (token, key string, err error) {
	switch w := who.(type) {
	case *Identity:
		if w == nil || w.Token == "" {
			return "", "", errors.New("qauth: the Identity carries no token")
		}
		return w.Token, identityKey(w.Issuer, w.Subject), nil
	case Token:
		if c.verifier != nil {
			id, err := c.verifier.Verify(ctx, string(w))
			if err != nil {
				return "", "", err
			}
			return id.Token, identityKey(id.Issuer, id.Subject), nil
		}
		return string(w), "t:" + sha(string(w)) + "\n", nil
	}
	return "", "", errors.New("qauth: unknown Who")
}

func identityKey(issuer, subject string) string { return "i:" + issuer + "\n" + subject + "\n" }

// Permissions answers the person's roles and permissions in one app inside
// one organization, kept per person, app and org (see
// WithPermissionsCache). Errors: 401 when their session is over, 403/404
// when they are not a member of the org.
func (c *Client) Permissions(ctx context.Context, who Who, app, org string) (*Effective, error) {
	token, key, err := c.whoKey(ctx, who)
	if err != nil {
		return nil, err
	}
	e, err := c.perms.load(ctx, key+"p\n"+app+"\n"+org, func() (*Effective, error) {
		var e Effective
		q := url.Values{"app": {app}, "org": {org}}
		return ret(&e, c.bearer(token).call(ctx, http.MethodGet, "/v1/me/permissions", q, nil, &e))
	}, nil)
	if err != nil {
		return nil, err
	}
	// a copy: answers are shared through the cache
	cp := *e
	cp.Roles, cp.Permissions, cp.OrgPermissions = slices.Clone(e.Roles), slices.Clone(e.Permissions), slices.Clone(e.OrgPermissions)
	return &cp, nil
}

// Can reports whether the person may use the permission KEY (e.g.
// "contacts:read") of the app in the organization. Decide on permission
// keys, never on role names (roles are data each organization edits). It
// answers false when qAuth says they are not a member of the org (403/404);
// a 401 (session over) is an error.
func (c *Client) Can(ctx context.Context, who Who, app, org, permission string) (bool, error) {
	e, err := c.Permissions(ctx, who, app, org)
	if err != nil {
		if s := StatusOf(err); s == http.StatusForbidden || s == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return e.Has(permission), nil
}

// Orgs answers the person's organizations with their role in each, cached
// like Permissions.
func (c *Client) Orgs(ctx context.Context, who Who) ([]MyOrg, error) {
	token, key, err := c.whoKey(ctx, who)
	if err != nil {
		return nil, err
	}
	orgs, err := c.orgs.load(ctx, key+"o\n", func() ([]MyOrg, error) {
		p, err := c.As(token).Orgs(ctx)
		if err != nil {
			return nil, err
		}
		return p.Items, nil
	}, nil)
	return slices.Clone(orgs), err
}

// Forget drops what is cached about a person (sign-out, a role change you
// made): their *Identity, or the raw Token you used.
func (c *Client) Forget(ctx context.Context, who Who) {
	var prefixes []string
	switch w := who.(type) {
	case *Identity:
		if w != nil {
			prefixes = append(prefixes, identityKey(w.Issuer, w.Subject))
		}
	case Token:
		prefixes = append(prefixes, "t:"+sha(string(w))+"\n")
		if c.verifier != nil {
			if id, err := c.verifier.Verify(ctx, string(w)); err == nil {
				prefixes = append(prefixes, identityKey(id.Issuer, id.Subject))
			}
		}
	}
	for _, p := range prefixes {
		c.perms.forget(p)
		c.orgs.forget(p)
	}
}

// ValidateKeyOptions narrows ValidateKey.
type ValidateKeyOptions struct {
	// App limits the check to one of your apps: a key for another app is
	// not valid.
	App string
}

// ValidateKey checks an API key one of your customers' systems presented to
// YOUR API. A revoked, expired or unknown key answers Valid=false with no
// error. With WithKeyCache set, answers (valid or not) are kept that long,
// keyed on a hash of the key. Use KeyMay to check a permission.
func (c *Client) ValidateKey(ctx context.Context, apiKey string, o ValidateKeyOptions) (KeyCheck, error) {
	if apiKey == "" {
		return KeyCheck{}, nil
	}
	kc, err := c.keys.load(ctx, sha(apiKey)+"\n"+o.App, func() (KeyCheck, error) {
		h := http.Header{"X-Api-Key": {apiKey}}
		if o.App != "" {
			h.Set("X-Qauth-App", o.App)
		}
		var kc KeyCheck
		err := (&transport{c: c, header: h}).call(ctx, http.MethodPost, "/auth/validate", nil, nil, &kc)
		if StatusOf(err) == http.StatusUnauthorized {
			return KeyCheck{Valid: false}, nil
		}
		return kc, err
	}, nil)
	return kc.clone(), err
}

// ForgetKeys drops every kept ValidateKey answer (e.g. right after you
// revoked a key).
func (c *Client) ForgetKeys() { c.keys.forget("") }

func (c *Client) bearer(token string) *transport {
	return &transport{c: c, header: http.Header{"Authorization": {"Bearer " + token}}}
}

// transport sends one caller's requests and reads qAuth's envelope.
type transport struct {
	c      *Client
	header http.Header
}

// withHeader is the transport with one more header (for one request).
func (t *transport) withHeader(k, v string) *transport {
	h := t.header.Clone()
	if h == nil {
		h = http.Header{}
	}
	h.Set(k, v)
	return &transport{c: t.c, header: h}
}

type envelope struct {
	Success    *bool           `json:"success"`
	Message    string          `json:"message"`
	Data       json.RawMessage `json:"data"`
	Pagination *Pagination     `json:"pagination"`
	Error      *struct {
		Code    string              `json:"code"`
		Message string              `json:"message"`
		Fields  map[string][]string `json:"fields"`
	} `json:"error"`
	Meta struct {
		RequestID string `json:"request_id"`
	} `json:"meta"`
}

const maxBody = 16 << 20

func (t *transport) do(ctx context.Context, method, path string, q url.Values, body any) (*envelope, error) {
	// an empty, "." or ".." id would change which address is called
	for _, s := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if s == "" || s == "." || s == ".." {
			return nil, &Error{Code: CodeInvalidArgument, Message: "An id is empty or not valid; nothing was sent."}
		}
	}
	u := t.c.base + path
	if len(q) > 0 {
		for k, v := range q {
			if len(v) == 0 || v[0] == "" {
				q.Del(k)
			}
		}
		if enc := q.Encode(); enc != "" {
			u += "?" + enc
		}
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	if t.c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.c.timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range t.header {
		req.Header[k] = v
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "qauth-go/"+Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := t.c.hc.Do(req)
	if err != nil {
		msg := "Could not reach qAuth."
		if errors.Is(err, context.DeadlineExceeded) {
			msg = "qAuth did not answer in time."
		}
		return nil, &Error{Code: CodeUnavailable, Message: msg, Err: err}
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return nil, &Error{Status: res.StatusCode, Code: CodeUnexpectedRedirect, RequestID: res.Header.Get("X-Request-ID"),
			Message: "qAuth answered a redirect; it is not followed (check the base address)."}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, &Error{Status: 0, Code: CodeUnavailable, Message: "qAuth's answer could not be read.", Err: err}
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Success == nil {
		return nil, &Error{Status: res.StatusCode, Code: CodeBadResponse, RequestID: res.Header.Get("X-Request-ID"),
			Message: fmt.Sprintf("qAuth answered HTTP %d without its JSON envelope.", res.StatusCode), Err: err,
			RetryAfter: parseRetryAfter(res.Header.Get("Retry-After"), t.c.now())}
	}
	if res.StatusCode >= 300 || !*env.Success {
		if env.Meta.RequestID == "" {
			env.Meta.RequestID = res.Header.Get("X-Request-ID")
		}
		e := &Error{Status: res.StatusCode, Code: "ERROR", Message: env.Message, RequestID: env.Meta.RequestID,
			RetryAfter: parseRetryAfter(res.Header.Get("Retry-After"), t.c.now())}
		if env.Error != nil {
			if env.Error.Code != "" {
				e.Code = env.Error.Code
			}
			if env.Error.Message != "" {
				e.Message = env.Error.Message
			}
			e.Fields = env.Error.Fields
		}
		if e.Message == "" {
			e.Message = fmt.Sprintf("HTTP %d", res.StatusCode)
		}
		return nil, e
	}
	return &env, nil
}

// call sends a request and decodes data into out (nil: ignore it).
func (t *transport) call(ctx context.Context, method, path string, q url.Values, body, out any) error {
	env, err := t.do(ctx, method, path, q, body)
	if err != nil {
		return err
	}
	if out == nil || len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return &Error{Status: http.StatusOK, Code: CodeBadResponse, Message: "qAuth's answer has an unexpected shape.", RequestID: env.Meta.RequestID, Err: err}
	}
	return nil
}

func list[T any](ctx context.Context, t *transport, path string, q url.Values) (*Page[T], error) {
	env, err := t.do(ctx, http.MethodGet, path, q, nil)
	if err != nil {
		return nil, err
	}
	p := &Page[T]{Items: []T{}}
	if len(env.Data) > 0 && string(env.Data) != "null" {
		if err := json.Unmarshal(env.Data, &p.Items); err != nil {
			return nil, &Error{Status: http.StatusOK, Code: CodeBadResponse, Message: "qAuth's answer has an unexpected shape.", RequestID: env.Meta.RequestID, Err: err}
		}
	}
	if env.Pagination != nil {
		p.Pagination = *env.Pagination
	}
	return p, nil
}

func seg(s string) string { return url.PathEscape(s) }

// ret answers v, or nil with the error.
func ret[T any](v *T, err error) (*T, error) {
	if err != nil {
		return nil, err
	}
	return v, nil
}
