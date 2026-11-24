package qauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// DefaultAlgorithms are the signing algorithms assumed when the issuer's
// discovery names none. Only public-key algorithms are ever accepted:
// "none" and HS* are always refused.
var DefaultAlgorithms = []string{"RS256", "ES256", "EdDSA"}

var allAsymmetric = []jose.SignatureAlgorithm{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

var asymmetric = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"EdDSA": true,
}

// VerifierConfig says which tokens a Verifier accepts. Issuers and
// ClientIDs are required.
type VerifierConfig struct {
	// Issuers are the accepted token issuers (exact match on iss), e.g.
	// "https://acme.qapps.dev". Each tenant has its own issuer. Discovery is
	// fetched only for these. https only (http only for localhost, 127.0.0.1
	// and ::1).
	Issuers []string
	// ClientIDs are the OAuth clients whose tokens your API accepts: checked
	// against the token's client_id (required). This is what restricts
	// which apps' tokens get in.
	ClientIDs []string
	// Audiences, when set: the token's aud must hold one of them. Empty
	// means any audience (only ClientIDs restrict).
	Audiences []string
	// Leeway is the allowed clock difference for exp, nbf and iat.
	// 0 means 60 seconds; a negative value means none.
	Leeway time.Duration
	// Algorithms narrows the accepted signing algorithms (public-key ones
	// only). Default: what the issuer's discovery publishes (or
	// DefaultAlgorithms when it publishes none).
	Algorithms []string
	// HTTPClient fetches discovery and keys. Default: a client with a 5 s
	// timeout that never follows redirects. Your own must do the same.
	HTTPClient *http.Client
	// FetchTimeout bounds each discovery or keys fetch, which runs apart
	// from the request that triggered it. 0 means 5 seconds.
	FetchTimeout time.Duration
	// KeysCooldown: a token signed with an unknown key id makes the Verifier
	// fetch the issuer's keys again, at most this often per issuer.
	// 0 means 30 seconds.
	KeysCooldown time.Duration
	// KeysMaxAge: the keys are fetched again after this long even when every
	// key id is known; if the issuer cannot be reached then, tokens are
	// refused with KEYS_UNAVAILABLE (503). 0 means 600 seconds.
	KeysMaxAge time.Duration
	// DiscoveryCacheTTL: each issuer's discovery document is kept this long
	// (then fetched again, as for KeysMaxAge). 0 means 3600 seconds. A failed
	// fetch is never kept.
	DiscoveryCacheTTL time.Duration
	// FailureBackoff: after a failed fetch, tokens of that issuer are
	// refused with KEYS_UNAVAILABLE at once for this long, without trying
	// again. 0 means 5 seconds.
	FailureBackoff time.Duration
	// Now is the clock (tests). Default time.Now.
	Now func() time.Time
}

// Identity is who a verified access token speaks for.
type Identity struct {
	// Subject is the person's (or machine's) id: the token's sub.
	Subject string
	// ClientID is the OAuth client the token was issued to (client_id).
	ClientID string
	// Issuer is the token's iss: the tenant's issuer.
	Issuer string
	// ExpiresAt is when the token stops working.
	ExpiresAt time.Time
	// Token is the raw access token, for calls to qAuth as the person.
	Token string
	// Claims are all the token's claims (numbers as json.Number).
	Claims map[string]any
}

// Verifier checks access tokens offline against the issuers' published keys.
// It is safe for concurrent use; create one per process and share it.
type Verifier struct {
	cfg      VerifierConfig
	narrow   []string // configured algorithms; nil = the issuer's
	leeway   time.Duration
	hc       *http.Client
	now      func() time.Time
	fetchTO  time.Duration
	cooldown time.Duration
	maxAge   time.Duration
	discTTL  time.Duration
	backoff  time.Duration

	mu      sync.Mutex
	issuers map[string]*issuerKeys
}

// issuerKeys is one issuer's discovery and keys. mu is never held during
// network I/O: a refresh runs in its own goroutine and callers wait on it.
type issuerKeys struct {
	mu          sync.Mutex
	jwksURI     string
	algs        []string // accepted: the issuer's (or default), narrowed by config
	discAt      time.Time
	keys        []jose.JSONWebKey
	keysAt      time.Time // last successful key fetch
	lastAttempt time.Time // last completed fetch for an unknown key id
	failedAt    time.Time // last failed fetch
	failErr     error
	inflight    *refresh
}

type refresh struct {
	done chan struct{}
	err  error
}

// noRedirect makes an http.Client answer a 3xx instead of following it.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// secureURL accepts https, or http for localhost, 127.0.0.1 and ::1.
func secureURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// NewVerifier checks the configuration and returns a Verifier. Nothing is
// fetched until the first token arrives.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if len(cfg.Issuers) == 0 {
		return nil, errors.New("qauth: VerifierConfig.Issuers is required")
	}
	if len(cfg.ClientIDs) == 0 {
		return nil, errors.New("qauth: VerifierConfig.ClientIDs is required")
	}
	for _, iss := range cfg.Issuers {
		if !secureURL(iss) {
			return nil, fmt.Errorf("qauth: issuer %q is not an https address (http only for localhost)", iss)
		}
	}
	for _, c := range cfg.ClientIDs {
		if c == "" {
			return nil, errors.New("qauth: VerifierConfig.ClientIDs holds an empty client id")
		}
	}
	if cfg.Algorithms != nil && len(cfg.Algorithms) == 0 {
		return nil, errors.New("qauth: VerifierConfig.Algorithms must not be empty")
	}
	v := &Verifier{cfg: cfg, issuers: map[string]*issuerKeys{}, narrow: cfg.Algorithms}
	for _, a := range cfg.Algorithms {
		if !asymmetric[a] {
			return nil, fmt.Errorf("qauth: algorithm %q is not allowed (public-key algorithms only)", a)
		}
	}
	v.leeway = cfg.Leeway
	switch {
	case v.leeway == 0:
		v.leeway = 60 * time.Second
	case v.leeway < 0:
		v.leeway = 0
	}
	v.hc = cfg.HTTPClient
	if v.hc == nil {
		v.hc = &http.Client{Timeout: 5 * time.Second, CheckRedirect: noRedirect}
	}
	v.now = cfg.Now
	if v.now == nil {
		v.now = time.Now
	}
	v.fetchTO = orDefault(cfg.FetchTimeout, 5*time.Second)
	v.cooldown = orDefault(cfg.KeysCooldown, 30*time.Second)
	v.maxAge = orDefault(cfg.KeysMaxAge, 600*time.Second)
	v.discTTL = orDefault(cfg.DiscoveryCacheTTL, time.Hour)
	v.backoff = orDefault(cfg.FailureBackoff, 5*time.Second)
	return v, nil
}

// idTokenClaims are claims access tokens never carry (ID tokens do): such a
// token is never accepted as an access token.
var idTokenClaims = []string{"azp", "at_hash", "nonce", "auth_time", "sid", "amr"}

// accessTyps are the accepted typ headers (absent is accepted too).
var accessTyps = []string{"jwt", "at+jwt", "application/at+jwt"}

// Verify checks an access token and answers who it speaks for. ID tokens
// (azp, at_hash, nonce, auth_time, sid or amr present; a typ other than
// JWT or at+jwt) are refused with CodeNotAccessToken. A refused token is an
// *Error with status 401 and one of the token codes (CodeTokenExpired,
// CodeWrongIssuer, CodeWrongClient, CodeBadSignature, CodeTokenMalformed...);
// CodeKeysUnavailable (503) when the issuer's keys could not be fetched.
func (v *Verifier) Verify(ctx context.Context, token string) (*Identity, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, tokenErr(CodeTokenMissing, "No access token was sent.", nil)
	}
	alg, kid, typ, err := peekHeader(token)
	if err != nil {
		return nil, tokenErr(CodeTokenMalformed, "The access token is not a signed JWT.", err)
	}
	if typ != "" && !slices.Contains(accessTyps, strings.ToLower(typ)) {
		return nil, tokenErr(CodeNotAccessToken, "This is not an access token.", nil)
	}
	if !asymmetric[alg] || (v.narrow != nil && !slices.Contains(v.narrow, alg)) {
		return nil, tokenErr(CodeBadSignature, fmt.Sprintf("The token's algorithm %q is not accepted.", alg), nil)
	}
	tok, err := jwt.ParseSigned(token, allAsymmetric)
	if err != nil {
		return nil, tokenErr(CodeTokenMalformed, "The access token is not a signed JWT.", err)
	}
	var unsafe json.RawMessage
	if err := tok.UnsafeClaimsWithoutVerification(&unsafe); err != nil {
		return nil, tokenErr(CodeTokenMalformed, "The access token's claims cannot be read.", err)
	}
	pre, err := decodeClaims(unsafe)
	if err != nil {
		return nil, err
	}
	// the issuer must be one of ours BEFORE anything is fetched for it
	iss, _ := pre["iss"].(string)
	if iss == "" || !slices.Contains(v.cfg.Issuers, iss) {
		return nil, tokenErr(CodeWrongIssuer, "The token is from an issuer this API does not accept.", nil)
	}
	keys, err := v.keysFor(ctx, iss, alg, kid)
	if err != nil {
		return nil, err
	}
	var payload json.RawMessage
	verified := false
	for _, k := range keys {
		if err := tok.Claims(k.Key, &payload); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, tokenErr(CodeBadSignature, "The token's signature is not valid.", nil)
	}
	all, err := decodeClaims(payload)
	if err != nil {
		return nil, err
	}
	return v.checkClaims(all, token)
}

// decodeClaims reads the payload into one case-sensitive map (numbers kept
// exact); every check reads from it.
func decodeClaims(b []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var all map[string]any
	if err := d.Decode(&all); err != nil || all == nil {
		return nil, tokenErr(CodeTokenMalformed, "The access token's claims cannot be read.", err)
	}
	return all, nil
}

// numericDate reads a NumericDate claim; ok=false when absent, err when not a number.
func numericDate(all map[string]any, name string) (t time.Time, ok bool, err error) {
	raw, ok := all[name]
	if !ok {
		return time.Time{}, false, nil
	}
	n, isNum := raw.(json.Number)
	if !isNum {
		return time.Time{}, true, tokenErr(CodeTokenMalformed, fmt.Sprintf("The token's %s is not a number.", name), nil)
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return time.Time{}, true, tokenErr(CodeTokenMalformed, fmt.Sprintf("The token's %s is not a number.", name), err)
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), true, nil
}

// audiences reads aud: a string or a list of strings.
func audiences(all map[string]any) ([]string, error) {
	switch a := all["aud"].(type) {
	case nil:
		return nil, nil
	case string:
		return []string{a}, nil
	case []any:
		out := make([]string, 0, len(a))
		for _, x := range a {
			s, ok := x.(string)
			if !ok {
				return nil, tokenErr(CodeTokenMalformed, "The token's aud is not a list of strings.", nil)
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, tokenErr(CodeTokenMalformed, "The token's aud is not a string or a list.", nil)
}

func (v *Verifier) checkClaims(all map[string]any, token string) (*Identity, error) {
	now := v.now()
	for _, k := range idTokenClaims {
		if _, ok := all[k]; ok {
			return nil, tokenErr(CodeNotAccessToken, "This is an ID token, not an access token.", nil)
		}
	}
	sub, _ := all["sub"].(string)
	if sub == "" {
		return nil, tokenErr(CodeTokenMalformed, "The token names no subject.", nil)
	}
	exp, ok, err := numericDate(all, "exp")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, tokenErr(CodeTokenMalformed, "The token has no expiry.", nil)
	}
	if now.After(exp.Add(v.leeway)) {
		return nil, tokenErr(CodeTokenExpired, "The token has expired.", nil)
	}
	for _, name := range []string{"nbf", "iat"} {
		t, ok, err := numericDate(all, name)
		if err != nil {
			return nil, err
		}
		if ok && t.After(now.Add(v.leeway)) {
			return nil, tokenErr(CodeNotYetValid, "The token is not valid yet.", nil)
		}
	}
	client, _ := all["client_id"].(string)
	if client == "" {
		return nil, tokenErr(CodeWrongClient, "The token names no client (client_id).", nil)
	}
	if !slices.Contains(v.cfg.ClientIDs, client) {
		return nil, tokenErr(CodeWrongClient, "The token was issued to a client this API does not accept.", nil)
	}
	aud, err := audiences(all)
	if err != nil {
		return nil, err
	}
	if len(v.cfg.Audiences) > 0 && !slices.ContainsFunc(v.cfg.Audiences, func(a string) bool { return slices.Contains(aud, a) }) {
		return nil, tokenErr(CodeWrongAudience, "The token is not meant for this API.", nil)
	}
	iss, _ := all["iss"].(string)
	return &Identity{Subject: sub, ClientID: client, Issuer: iss, ExpiresAt: exp, Token: token, Claims: all}, nil
}

// peekHeader reads alg, kid and typ from the JOSE header without trusting it.
func peekHeader(token string) (alg, kid, typ string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", errors.New("not three parts")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", "", err
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return "", "", "", err
	}
	return h.Alg, h.Kid, h.Typ, nil
}

// keysFor answers the issuer's keys that may have signed a token with this
// alg and kid, fetching discovery and keys when needed. Fetches run apart
// from the caller (its cancellation never cuts one short) and are shared by
// every caller waiting for them; a caller stops waiting when its ctx ends.
func (v *Verifier) keysFor(ctx context.Context, iss, alg, kid string) ([]jose.JSONWebKey, error) {
	v.mu.Lock()
	ik := v.issuers[iss]
	if ik == nil {
		ik = &issuerKeys{}
		v.issuers[iss] = ik
	}
	v.mu.Unlock()

	for range 4 { // discovery, keys, an unknown key id: each settles in one round
		ik.mu.Lock()
		now := v.now()
		needDisc := ik.discAt.IsZero() || now.Sub(ik.discAt) >= v.discTTL
		needKeys := ik.keysAt.IsZero() || now.Sub(ik.keysAt) >= v.maxAge
		unknown := false
		if !needDisc && !needKeys {
			if !slices.Contains(ik.algs, alg) {
				ik.mu.Unlock()
				return nil, tokenErr(CodeBadSignature, fmt.Sprintf("The issuer does not sign with %q.", alg), nil)
			}
			if found := matchKeys(ik.keys, alg, kid); len(found) > 0 {
				ik.mu.Unlock()
				return found, nil
			}
			if !ik.lastAttempt.IsZero() && now.Sub(ik.lastAttempt) < v.cooldown {
				ik.mu.Unlock()
				return nil, tokenErr(CodeBadSignature, "The token is signed with a key the issuer does not publish.", nil)
			}
			unknown = true // maybe the issuer rotated
		}
		f := ik.inflight
		if f == nil {
			if !ik.failedAt.IsZero() && now.Sub(ik.failedAt) < v.backoff {
				err := ik.failErr
				ik.mu.Unlock()
				return nil, err // the issuer just failed: answer at once
			}
			f = &refresh{done: make(chan struct{})}
			ik.inflight = f
			go v.refresh(context.WithoutCancel(ctx), iss, ik, f, needDisc, unknown)
		}
		ik.mu.Unlock()
		select {
		case <-f.done:
			if f.err != nil {
				return nil, f.err
			}
		case <-ctx.Done():
			return nil, tokenErr(CodeKeysUnavailable, "The issuer's keys were not ready in time.", ctx.Err())
		}
	}
	return nil, tokenErr(CodeKeysUnavailable, "The issuer's keys could not be settled.", nil)
}

// refresh fetches discovery (when due) and the keys, then applies them.
func (v *Verifier) refresh(ctx context.Context, iss string, ik *issuerKeys, f *refresh, needDisc, unknown bool) {
	ctx, cancel := context.WithTimeout(ctx, v.fetchTO)
	defer cancel()
	ik.mu.Lock()
	jwksURI, algs := ik.jwksURI, ik.algs
	ik.mu.Unlock()
	var err error
	if needDisc {
		jwksURI, algs, err = v.discover(ctx, iss)
	}
	var keys []jose.JSONWebKey
	if err == nil {
		keys, err = v.fetchKeys(ctx, jwksURI)
	}
	ik.mu.Lock()
	now := v.now()
	if err != nil {
		ik.failedAt, ik.failErr = now, err
	} else {
		if needDisc {
			ik.jwksURI, ik.algs, ik.discAt = jwksURI, algs, now
		}
		ik.keys, ik.keysAt = keys, now
		ik.failedAt, ik.failErr = time.Time{}, nil
	}
	if unknown {
		ik.lastAttempt = now // only once the fetch is done
	}
	f.err = err
	ik.inflight = nil
	ik.mu.Unlock()
	close(f.done)
}

func matchKeys(keys []jose.JSONWebKey, alg, kid string) []jose.JSONWebKey {
	var out []jose.JSONWebKey
	for _, k := range keys {
		if kid != "" && k.KeyID != kid {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != alg {
			continue
		}
		if !keyFits(k.Key, alg) {
			continue
		}
		out = append(out, k)
	}
	return out
}

// keyFits: the key's type is the one the algorithm needs.
func keyFits(key any, alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		_, ok := key.(*rsa.PublicKey)
		return ok
	case "ES256", "ES384", "ES512":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		want := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}[alg]
		return k.Curve == want
	case "EdDSA":
		_, ok := key.(ed25519.PublicKey)
		return ok
	}
	return false
}

const maxDoc = 1 << 20

// discover reads the issuer's discovery document.
func (v *Verifier) discover(ctx context.Context, iss string) (jwksURI string, algs []string, err error) {
	var disc struct {
		Issuer  string   `json:"issuer"`
		JWKSURI string   `json:"jwks_uri"`
		Algs    []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := v.getJSON(ctx, strings.TrimSuffix(iss, "/")+"/.well-known/openid-configuration", &disc); err != nil {
		return "", nil, tokenErr(CodeKeysUnavailable, "Could not read the issuer's sign-in settings. Please try again.", err)
	}
	if disc.Issuer != iss {
		return "", nil, tokenErr(CodeKeysUnavailable, "The issuer's discovery document names another issuer.", nil)
	}
	if !secureURL(disc.JWKSURI) {
		return "", nil, tokenErr(CodeKeysUnavailable, "The issuer's discovery document names no https keys address.", nil)
	}
	published := disc.Algs
	if len(published) == 0 {
		published = DefaultAlgorithms
	}
	for _, a := range published {
		if asymmetric[a] && (v.narrow == nil || slices.Contains(v.narrow, a)) {
			algs = append(algs, a)
		}
	}
	if len(algs) == 0 {
		return "", nil, tokenErr(CodeKeysUnavailable, "The issuer publishes no public-key algorithm this API accepts.", nil)
	}
	return disc.JWKSURI, algs, nil
}

// fetchKeys reads the issuer's keys.
func (v *Verifier) fetchKeys(ctx context.Context, jwksURI string) ([]jose.JSONWebKey, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := v.getJSON(ctx, jwksURI, &set); err != nil {
		return nil, tokenErr(CodeKeysUnavailable, "Could not fetch the issuer's keys. Please try again.", err)
	}
	var keys []jose.JSONWebKey
	for _, raw := range set.Keys {
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(raw); err != nil || !k.Valid() || !k.IsPublic() {
			continue // skip a key we cannot use; never accept a private or symmetric one
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

func (v *Verifier) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := v.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s (redirects are not followed)", res.StatusCode, url)
	}
	return json.NewDecoder(io.LimitReader(res.Body, maxDoc)).Decode(out)
}
