package qauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// DefaultTrustedAPIHosts are the qAuth API hosts (host[:port]) an issuer's
// discovery may name as qauth_api unless WithTrustedAPIHosts says otherwise.
var DefaultTrustedAPIHosts = []string{"auth.qapps.dev"}

// WithTrustedAPIHosts replaces the qAuth API hosts (host[:port]) FromIssuer
// accepts as an issuer's qauth_api (default DefaultTrustedAPIHosts). The
// issuer is the trust root for tokens only: an issuer naming any other API
// address is refused, so a tenant's DNS can't send your tokens and keys
// elsewhere. Your own qAuth (staging, self-hosted): name its host here, or
// use New with its address.
func WithTrustedAPIHosts(hosts ...string) Option {
	return func(c *Client) { c.trustedAPI = append([]string{}, hosts...) }
}

// WithAPIKey sets an organization's API key (qak_...) for machine calls:
// Client.Org uses it.
func WithAPIKey(apiKey string) Option { return func(c *Client) { c.apiKey = apiKey } }

// FromIssuer returns a Client set up from your tenant's issuer (e.g.
// https://acme.qapps.dev) and your app's client id alone: qAuth's API
// address is read once from the issuer's discovery document (qauth_api),
// and a Verifier for that issuer and client is built and wired in
// (WithVerifier), unless you pass your own. WithAPIKey adds an
// organization's API key for Client.Org.
//
// The issuer must be https (http only for localhost); discovery's issuer
// must be exactly it, its qauth_api must be https (http only for
// localhost), and redirects are never followed. A qAuth server without
// qauth_api in discovery is older: use New with its address.
func FromIssuer(ctx context.Context, issuer, clientID string, opts ...Option) (*Client, error) {
	if !secureURL(issuer) {
		return nil, fmt.Errorf("qauth: issuer %q is not an https address (http only for localhost)", issuer)
	}
	if clientID == "" {
		return nil, fmt.Errorf("qauth: the client id is required")
	}
	// the options as given: their HTTP client and timeout read discovery too
	given := &Client{timeout: 15 * time.Second}
	for _, o := range opts {
		o(given)
	}
	// never follow a redirect, whatever client was given (a copy: the
	// caller's own client is left as it is)
	var hc *http.Client
	if given.hc != nil {
		cp := *given.hc
		cp.CheckRedirect = noRedirect
		hc = &cp
		opts = append(opts, WithHTTPClient(hc))
	}
	disc := hc
	if disc == nil {
		disc = &http.Client{CheckRedirect: noRedirect}
	}
	trusted := given.trustedAPI
	if trusted == nil {
		trusted = DefaultTrustedAPIHosts
	}
	api, err := discoverAPI(ctx, disc, given.timeout, issuer, trusted)
	if err != nil {
		return nil, err
	}
	if given.verifier == nil {
		v, err := NewVerifier(VerifierConfig{Issuers: []string{issuer}, ClientIDs: []string{clientID}, HTTPClient: hc})
		if err != nil {
			return nil, err
		}
		opts = append([]Option{WithVerifier(v)}, opts...)
	}
	return New(api, opts...)
}

// discoverAPI reads qauth_api from the issuer's discovery document.
func discoverAPI(ctx context.Context, hc *http.Client, timeout time.Duration, issuer string, trusted []string) (string, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "qauth-go/"+Version)
	res, err := hc.Do(req)
	if err != nil {
		return "", &Error{Code: CodeUnavailable, Message: "Could not read the issuer's sign-in settings.", Err: err}
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return "", &Error{Status: res.StatusCode, Code: CodeUnexpectedRedirect, Message: "The issuer's discovery answered a redirect; it is not followed."}
	}
	if res.StatusCode != http.StatusOK {
		return "", &Error{Status: res.StatusCode, Code: CodeUnavailable, Message: fmt.Sprintf("The issuer's discovery answered HTTP %d.", res.StatusCode)}
	}
	var doc struct {
		Issuer   string `json:"issuer"`
		QAuthAPI string `json:"qauth_api"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, maxDoc)).Decode(&doc); err != nil {
		return "", &Error{Status: res.StatusCode, Code: CodeBadResponse, Message: "The issuer's discovery is not a JSON document.", Err: err}
	}
	if doc.Issuer != issuer {
		return "", &Error{Status: res.StatusCode, Code: CodeBadResponse, Message: "The issuer's discovery document names another issuer."}
	}
	if doc.QAuthAPI == "" {
		return "", &Error{Status: res.StatusCode, Code: CodeBadResponse, Message: "The issuer's discovery names no qAuth API (qauth_api): this qAuth server is older; use New with its address."}
	}
	if !secureURL(doc.QAuthAPI) {
		return "", &Error{Status: res.StatusCode, Code: CodeBadResponse, Message: "The qAuth API the issuer names is not an https address."}
	}
	api, _ := url.Parse(doc.QAuthAPI)
	if !slices.ContainsFunc(trusted, func(h string) bool { return strings.EqualFold(h, api.Host) }) {
		return "", &Error{Status: res.StatusCode, Code: CodeUntrustedAPI, Message: "This issuer names an API address that isn't a known qAuth address; use New with its address (or WithTrustedAPIHosts) if you run your own qAuth."}
	}
	return strings.TrimRight(doc.QAuthAPI, "/"), nil
}

// Org is one organization with the API key set by WithAPIKey (machine
// calls; see WithKey). Without a key, qAuth refuses the calls (401).
func (c *Client) Org(orgID string) *OrgClient { return c.WithKey(c.apiKey).Org(orgID) }

// Verifier is the token Verifier the Client uses (yours, or the one
// FromIssuer built); nil when there is none. Use it to protect your routes
// (Verifier.Middleware).
func (c *Client) Verifier() *Verifier { return c.verifier }

// BaseURL is qAuth's API address the Client calls.
func (c *Client) BaseURL() string { return c.base }
