package qauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIssuer serves discovery and JWKS; keys are generated in the test.
type fakeIssuer struct {
	srv          *httptest.Server
	mu           sync.Mutex
	keys         []jose.JSONWebKey // published (public) keys
	extraKeys    []json.RawMessage // published as-is (to test skipping)
	algs         []string
	discIss      string        // issuer named in discovery ("" = the real one)
	jwksOverride string        // jwks_uri named in discovery ("" = ours)
	hold         chan struct{} // when set, every answer waits for it
	down         bool
	extra        map[string]any // more discovery fields (qauth_api)
	redirect     string         // discovery answers a redirect there
	discHits     atomic.Int32
	jwksHits     atomic.Int32
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	f := &fakeIssuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.discHits.Add(1)
		f.wait()
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.down {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		if f.redirect != "" {
			http.Redirect(w, r, f.redirect, http.StatusFound)
			return
		}
		iss := f.discIss
		if iss == "" {
			iss = f.srv.URL
		}
		jwks := f.srv.URL + "/keys"
		if f.jwksOverride != "" {
			jwks = f.jwksOverride
		}
		d := map[string]any{"issuer": iss, "jwks_uri": jwks}
		if f.algs != nil {
			d["id_token_signing_alg_values_supported"] = f.algs
		}
		for k, v := range f.extra {
			d[k] = v
		}
		_ = json.NewEncoder(w).Encode(d)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		f.jwksHits.Add(1)
		f.wait()
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.down {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		var keys []json.RawMessage
		for _, k := range f.keys {
			b, _ := k.MarshalJSON()
			keys = append(keys, b)
		}
		keys = append(keys, f.extraKeys...)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) wait() {
	f.mu.Lock()
	h := f.hold
	f.mu.Unlock()
	if h != nil {
		<-h
	}
}

func (f *fakeIssuer) publish(k signingKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, jose.JSONWebKey{Key: k.pub, KeyID: k.kid, Algorithm: string(k.alg), Use: "sig"})
}

func (f *fakeIssuer) set(fn func(f *fakeIssuer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

type signingKey struct {
	kid  string
	alg  jose.SignatureAlgorithm
	priv crypto.Signer
	pub  crypto.PublicKey
}

func newKey(t *testing.T, kid string, alg jose.SignatureAlgorithm) signingKey {
	t.Helper()
	var priv crypto.Signer
	var err error
	switch alg {
	case jose.RS256:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case jose.ES256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.EdDSA:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	return signingKey{kid: kid, alg: alg, priv: priv, pub: priv.Public()}
}

func sign(t *testing.T, k signingKey, claims map[string]any) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: k.alg, Key: jose.JSONWebKey{Key: k.priv, KeyID: k.kid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// handMade builds a token with any header and an HMAC (or no) signature.
func handMade(header, claims map[string]any, hmacKey []byte) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	if hmacKey == nil {
		return in + "."
	}
	m := hmac.New(sha256.New, hmacKey)
	m.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

var t0 = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func setup(t *testing.T, mod ...func(*VerifierConfig)) (*Verifier, *fakeIssuer, signingKey, *clock) {
	t.Helper()
	f := newFakeIssuer(t)
	k := newKey(t, "k1", jose.RS256)
	f.publish(k)
	clk := &clock{t: t0}
	cfg := VerifierConfig{Issuers: []string{f.srv.URL}, ClientIDs: []string{"web-client"}, Now: clk.now}
	for _, m := range mod {
		m(&cfg)
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v, f, k, clk
}

func claimsFor(f *fakeIssuer, over map[string]any) map[string]any {
	c := map[string]any{"iss": f.srv.URL, "sub": "user-1", "client_id": "web-client", "aud": []string{"web-client", "project-1"},
		"exp": t0.Add(15 * time.Minute).Unix(), "iat": t0.Unix(), "nbf": t0.Unix(), "jti": "j1"}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func wantCode(t *testing.T, err error, target *Error, status int) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("want %s, got %v", target.Code, err)
	}
	if StatusOf(err) != status {
		t.Fatalf("want status %d, got %d (%v)", status, StatusOf(err), err)
	}
}

func TestVerifyAcceptsEachAlgorithm(t *testing.T) {
	ctx := context.Background()
	for _, alg := range []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			v, f, _, _ := setup(t)
			k := newKey(t, "k-"+string(alg), alg)
			f.publish(k)
			id, err := v.Verify(ctx, sign(t, k, claimsFor(f, nil)))
			if err != nil {
				t.Fatal(err)
			}
			if id.Subject != "user-1" || id.ClientID != "web-client" || id.Issuer != f.srv.URL ||
				!id.ExpiresAt.Equal(t0.Add(15*time.Minute)) || id.Claims["jti"] != "j1" || id.Token == "" {
				t.Fatalf("identity: %+v", id)
			}
		})
	}
}

// stagingAccess and stagingID are shaped exactly like qAuth's real tokens
// (staging): the access token's claims, and the ID token's.
func stagingAccess(f *fakeIssuer) map[string]any {
	return map[string]any{"aud": []string{"web-client", "project-1"}, "client_id": "web-client",
		"exp": t0.Add(15 * time.Minute).Unix(), "iat": t0.Unix(), "iss": f.srv.URL, "jti": "V2_3456",
		"nbf": t0.Unix(), "sub": "user-1"}
}

func stagingID(f *fakeIssuer) map[string]any {
	return map[string]any{"amr": []string{"pwd"}, "at_hash": "x4Ym3WqZ", "aud": []string{"web-client", "project-1"},
		"auth_time": t0.Add(-time.Minute).Unix(), "azp": "web-client", "client_id": "web-client",
		"email": "sara@shop.test", "email_verified": true, "name": "Sara", "exp": t0.Add(time.Hour).Unix(),
		"iat": t0.Unix(), "iss": f.srv.URL, "sid": "V1_sess", "sub": "user-1"}
}

func TestVerifyStagingShapes(t *testing.T) {
	ctx := context.Background()
	v, f, k, _ := setup(t)
	id, err := v.Verify(ctx, sign(t, k, stagingAccess(f)))
	if err != nil || id.Subject != "user-1" || id.ClientID != "web-client" {
		t.Fatalf("access token: %v %+v", err, id)
	}
	_, err = v.Verify(ctx, sign(t, k, stagingID(f)))
	wantCode(t, err, ErrNotAccessToken, 401)
}

func TestVerifyRefusesIDTokenClaims(t *testing.T) {
	ctx := context.Background()
	v, f, k, _ := setup(t)
	for _, claim := range []string{"azp", "at_hash", "nonce", "auth_time", "sid", "amr"} {
		c := stagingAccess(f)
		c[claim] = "web-client"
		if claim == "auth_time" {
			c[claim] = t0.Unix()
		}
		_, err := v.Verify(ctx, sign(t, k, c))
		wantCode(t, err, ErrNotAccessToken, 401)
	}
	// no client_id: no azp fallback
	c := stagingAccess(f)
	delete(c, "client_id")
	_, err := v.Verify(ctx, sign(t, k, c))
	wantCode(t, err, ErrWrongClient, 401)
	// sub must be a non-empty string
	for _, sub := range []any{"", 42, []string{"user-1"}, nil} {
		c := stagingAccess(f)
		c["sub"] = sub
		if sub == nil {
			delete(c, "sub")
		}
		_, err := v.Verify(ctx, sign(t, k, c))
		wantCode(t, err, ErrTokenMalformed, 401)
	}
}

func signTyp(t *testing.T, k signingKey, typ string, claims map[string]any) string {
	t.Helper()
	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: k.alg, Key: jose.JSONWebKey{Key: k.priv, KeyID: k.kid}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestVerifyTyp(t *testing.T) {
	ctx := context.Background()
	v, f, k, _ := setup(t)
	for _, typ := range []string{"", "JWT", "at+jwt", "application/at+jwt"} {
		if _, err := v.Verify(ctx, signTyp(t, k, typ, stagingAccess(f))); err != nil {
			t.Fatalf("typ %q: %v", typ, err)
		}
	}
	for _, typ := range []string{"id+jwt", "logout+jwt", "JOSE"} {
		_, err := v.Verify(ctx, signTyp(t, k, typ, stagingAccess(f)))
		wantCode(t, err, ErrNotAccessToken, 401)
	}
}

func TestVerifyRefusals(t *testing.T) {
	ctx := context.Background()
	v, f, k, _ := setup(t, func(c *VerifierConfig) { c.Audiences = []string{"project-1"} })
	other := newKey(t, "k1", jose.RS256) // same kid, not the issuer's key
	cases := []struct {
		name   string
		token  string
		want   *Error
		status int
	}{
		{"missing", "", ErrTokenMissing, 401},
		{"not a JWT", "abc", ErrTokenMalformed, 401},
		{"garbage parts", "a.b.c", ErrTokenMalformed, 401},
		{"expired", sign(t, k, claimsFor(f, map[string]any{"exp": t0.Add(-61 * time.Second).Unix()})), ErrTokenExpired, 401},
		{"not yet valid", sign(t, k, claimsFor(f, map[string]any{"nbf": t0.Add(2 * time.Minute).Unix()})), ErrNotYetValid, 401},
		{"issued in the future", sign(t, k, claimsFor(f, map[string]any{"iat": t0.Add(2 * time.Minute).Unix()})), ErrNotYetValid, 401},
		{"wrong issuer", sign(t, k, claimsFor(f, map[string]any{"iss": "https://evil.example"})), ErrWrongIssuer, 401},
		{"issuer with a slash", sign(t, k, claimsFor(f, map[string]any{"iss": f.srv.URL + "/"})), ErrWrongIssuer, 401},
		{"wrong client", sign(t, k, claimsFor(f, map[string]any{"client_id": "someone-else"})), ErrWrongClient, 401},
		{"no client", sign(t, k, claimsFor(f, map[string]any{"client_id": nil})), ErrWrongClient, 401},
		{"wrong audience", sign(t, k, claimsFor(f, map[string]any{"aud": "another-api"})), ErrWrongAudience, 401},
		{"no subject", sign(t, k, claimsFor(f, map[string]any{"sub": nil})), ErrTokenMalformed, 401},
		{"no expiry", sign(t, k, claimsFor(f, map[string]any{"exp": nil})), ErrTokenMalformed, 401},
		{"bad signature", sign(t, other, claimsFor(f, nil)), ErrBadSignature, 401},
		{"alg none", handMade(map[string]any{"alg": "none", "kid": "k1"}, claimsFor(f, nil), nil), ErrBadSignature, 401},
		{"tampered payload", tamper(sign(t, k, claimsFor(f, nil)), claimsFor(f, map[string]any{"sub": "admin"})), ErrBadSignature, 401},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.Verify(ctx, c.token)
			wantCode(t, err, c.want, c.status)
		})
	}
}

func tamper(token string, claims map[string]any) string {
	parts := strings.Split(token, ".")
	b, _ := json.Marshal(claims)
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(b) + "." + parts[2]
}

func TestVerifyLeeway(t *testing.T) {
	ctx := context.Background()
	v, f, k, _ := setup(t)
	// 59 s past expiry is inside the default 60 s
	if _, err := v.Verify(ctx, sign(t, k, claimsFor(f, map[string]any{"exp": t0.Add(-59 * time.Second).Unix()}))); err != nil {
		t.Fatal(err)
	}
	strict, f2, k2, _ := setup(t, func(c *VerifierConfig) { c.Leeway = -1 })
	_, err := strict.Verify(ctx, sign(t, k2, claimsFor(f2, map[string]any{"exp": t0.Add(-1 * time.Second).Unix()})))
	wantCode(t, err, ErrTokenExpired, 401)
}

// HS256 signed with the issuer's RSA public key as the secret: the classic
// algorithm-confusion attack. Refused before any key is used.
func TestVerifyRefusesHMACWithPublicKey(t *testing.T) {
	v, f, k, _ := setup(t)
	der, _ := x509.MarshalPKIXPublicKey(k.pub)
	tok := handMade(map[string]any{"alg": "HS256", "kid": "k1", "typ": "JWT"}, claimsFor(f, nil), der)
	_, err := v.Verify(context.Background(), tok)
	wantCode(t, err, ErrBadSignature, 401)
	// a symmetric key published in the JWKS is never used either
	f.set(func(f *fakeIssuer) {
		f.extraKeys = append(f.extraKeys, json.RawMessage(`{"kty":"oct","kid":"h1","k":"c2VjcmV0"}`))
	})
	tok = handMade(map[string]any{"alg": "HS256", "kid": "h1"}, claimsFor(f, nil), []byte("secret"))
	_, err = v.Verify(context.Background(), tok)
	wantCode(t, err, ErrBadSignature, 401)
}

func TestVerifyOnlyAlgorithmsTheIssuerStates(t *testing.T) {
	v, f, _, _ := setup(t)
	f.set(func(f *fakeIssuer) { f.algs = []string{"RS256"} })
	ec := newKey(t, "ec", jose.ES256)
	f.publish(ec)
	_, err := v.Verify(context.Background(), sign(t, ec, claimsFor(f, nil)))
	wantCode(t, err, ErrBadSignature, 401)
}

// A key published for one algorithm is not used for another, even with the
// right kid.
func TestVerifyKeyAlgorithmMustMatch(t *testing.T) {
	v, f, _, _ := setup(t)
	ec := newKey(t, "ec", jose.ES256)
	f.set(func(f *fakeIssuer) {
		f.keys = append(f.keys, jose.JSONWebKey{Key: ec.pub, KeyID: "ec", Algorithm: "ES384", Use: "sig"})
	})
	_, err := v.Verify(context.Background(), sign(t, ec, claimsFor(f, nil)))
	wantCode(t, err, ErrBadSignature, 401)
}

func TestNewVerifierConfig(t *testing.T) {
	for name, cfg := range map[string]VerifierConfig{
		"no issuers":    {ClientIDs: []string{"c"}},
		"no clients":    {Issuers: []string{"https://a"}},
		"not http":      {Issuers: []string{"a.example"}, ClientIDs: []string{"c"}},
		"plain http":    {Issuers: []string{"http://acme.qapps.dev"}, ClientIDs: []string{"c"}},
		"HMAC":          {Issuers: []string{"https://a"}, ClientIDs: []string{"c"}, Algorithms: []string{"HS256"}},
		"none":          {Issuers: []string{"https://a"}, ClientIDs: []string{"c"}, Algorithms: []string{"none"}},
		"mixed in HMAC": {Issuers: []string{"https://a"}, ClientIDs: []string{"c"}, Algorithms: []string{"RS256", "HS512"}},
		"empty algs":    {Issuers: []string{"https://a"}, ClientIDs: []string{"c"}, Algorithms: []string{}},
		"empty client":  {Issuers: []string{"https://a"}, ClientIDs: []string{""}},
	} {
		if _, err := NewVerifier(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A wrong issuer is refused before anything is fetched (no request to an
// address an attacker put in the token).
func TestVerifyWrongIssuerFetchesNothing(t *testing.T) {
	v, _, _, _ := setup(t)
	evil := newFakeIssuer(t)
	ek := newKey(t, "k1", jose.RS256)
	evil.publish(ek)
	_, err := v.Verify(context.Background(), sign(t, ek, claimsFor(evil, nil)))
	wantCode(t, err, ErrWrongIssuer, 401)
	if evil.discHits.Load()+evil.jwksHits.Load() != 0 {
		t.Fatal("fetched from an issuer that is not configured")
	}
}

func TestVerifyKeysUnavailable(t *testing.T) {
	v, f, k, _ := setup(t)
	f.set(func(f *fakeIssuer) { f.down = true })
	_, err := v.Verify(context.Background(), sign(t, k, claimsFor(f, nil)))
	wantCode(t, err, ErrKeysUnavailable, 503)

	v2, f2, k2, _ := setup(t)
	f2.set(func(f *fakeIssuer) { f.discIss = "https://someone-else.example" })
	_, err = v2.Verify(context.Background(), sign(t, k2, claimsFor(f2, nil)))
	wantCode(t, err, ErrKeysUnavailable, 503)
}

func TestVerifyKeyRotation(t *testing.T) {
	ctx := context.Background()
	v, f, k1, clk := setup(t)
	if _, err := v.Verify(ctx, sign(t, k1, claimsFor(f, nil))); err != nil {
		t.Fatal(err)
	}
	if f.jwksHits.Load() != 1 {
		t.Fatalf("jwks hits %d", f.jwksHits.Load())
	}
	// cached: no more fetches
	for range 3 {
		if _, err := v.Verify(ctx, sign(t, k1, claimsFor(f, nil))); err != nil {
			t.Fatal(err)
		}
	}
	if f.jwksHits.Load() != 1 {
		t.Fatalf("jwks hits %d", f.jwksHits.Load())
	}
	// the issuer rotates: a token with the new kid makes the keys be fetched again
	k2 := newKey(t, "k2", jose.RS256)
	f.publish(k2)
	if _, err := v.Verify(ctx, sign(t, k2, claimsFor(f, nil))); err != nil {
		t.Fatal(err)
	}
	if f.jwksHits.Load() != 2 {
		t.Fatalf("jwks hits %d", f.jwksHits.Load())
	}
	// an unknown kid inside the 30 s window fetches nothing more
	k3 := newKey(t, "k3", jose.RS256)
	f.publish(k3)
	_, err := v.Verify(ctx, sign(t, k3, claimsFor(f, nil)))
	wantCode(t, err, ErrBadSignature, 401)
	if f.jwksHits.Load() != 2 {
		t.Fatalf("refetched inside the window: %d", f.jwksHits.Load())
	}
	// after it, the new key is found
	clk.add(31 * time.Second)
	if _, err := v.Verify(ctx, sign(t, k3, claimsFor(f, map[string]any{"exp": clk.now().Add(time.Minute).Unix()}))); err != nil {
		t.Fatal(err)
	}
	if f.jwksHits.Load() != 3 {
		t.Fatalf("jwks hits %d", f.jwksHits.Load())
	}
	// the old key is retired: its tokens are refused once the keys are fetched again
	f.set(func(f *fakeIssuer) { f.keys = f.keys[1:] })
	clk.add(time.Hour)
	_, err = v.Verify(ctx, sign(t, k1, claimsFor(f, map[string]any{"exp": clk.now().Add(time.Minute).Unix()})))
	wantCode(t, err, ErrBadSignature, 401)
}

// Many concurrent tokens with an unknown kid cause one fetch, not a storm.
func TestVerifyUnknownKidConcurrent(t *testing.T) {
	ctx := context.Background()
	v, f, k1, _ := setup(t)
	if _, err := v.Verify(ctx, sign(t, k1, claimsFor(f, nil))); err != nil {
		t.Fatal(err)
	}
	stranger := newKey(t, "nope", jose.RS256)
	tok := sign(t, stranger, claimsFor(f, nil))
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = v.Verify(ctx, tok)
		}()
	}
	wg.Wait()
	if n := f.jwksHits.Load(); n != 2 {
		t.Fatalf("jwks hits %d, want 2", n)
	}
}

// Past KeysMaxAge (or the discovery TTL) the issuer must answer again: if it
// is down then, tokens are refused with 503, never checked with stale keys.
func TestVerifyRefreshFailureIs503(t *testing.T) {
	ctx := context.Background()
	for name, wait := range map[string]time.Duration{"keys max age": 601 * time.Second, "discovery TTL": 61 * time.Minute} {
		t.Run(name, func(t *testing.T) {
			v, f, k, clk := setup(t)
			if _, err := v.Verify(ctx, sign(t, k, claimsFor(f, nil))); err != nil {
				t.Fatal(err)
			}
			clk.add(wait)
			f.set(func(f *fakeIssuer) { f.down = true })
			fresh := claimsFor(f, map[string]any{"exp": clk.now().Add(time.Minute).Unix()})
			_, err := v.Verify(ctx, sign(t, k, fresh))
			wantCode(t, err, ErrKeysUnavailable, 503)
			f.set(func(f *fakeIssuer) { f.down = false })
			clk.add(6 * time.Second) // past the failure backoff
			if _, err := v.Verify(ctx, sign(t, k, fresh)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Only the configured algorithms are accepted, even when the issuer
// publishes a fitting key without an alg.
func TestVerifyConfiguredAlgorithmsOnly(t *testing.T) {
	v, f, _, _ := setup(t, func(c *VerifierConfig) { c.Algorithms = []string{"RS256"} })
	ec := newKey(t, "ec", jose.ES256)
	f.set(func(f *fakeIssuer) { f.keys = append(f.keys, jose.JSONWebKey{Key: ec.pub, KeyID: "ec"}) })
	_, err := v.Verify(context.Background(), sign(t, ec, claimsFor(f, nil)))
	wantCode(t, err, ErrBadSignature, 401)
}

// A failed discovery is never kept: after the short backoff (during which
// tokens fail fast, with no new fetch) the next token tries again.
func TestVerifyFailureNotCached(t *testing.T) {
	v, f, k, clk := setup(t)
	f.set(func(f *fakeIssuer) { f.down = true })
	_, err := v.Verify(context.Background(), sign(t, k, claimsFor(f, nil)))
	wantCode(t, err, ErrKeysUnavailable, 503)
	f.set(func(f *fakeIssuer) { f.down = false })
	_, err = v.Verify(context.Background(), sign(t, k, claimsFor(f, nil)))
	wantCode(t, err, ErrKeysUnavailable, 503)
	if f.discHits.Load() != 1 {
		t.Fatalf("discovery hits %d inside the backoff", f.discHits.Load())
	}
	clk.add(5 * time.Second)
	if _, err := v.Verify(context.Background(), sign(t, k, claimsFor(f, nil))); err != nil {
		t.Fatal(err)
	}
}

// Keys are fetched again after KeysMaxAge (600 s); discovery is kept for
// its own hour.
func TestVerifyKeysMaxAge(t *testing.T) {
	ctx := context.Background()
	v, f, k, clk := setup(t)
	if _, err := v.Verify(ctx, sign(t, k, claimsFor(f, nil))); err != nil {
		t.Fatal(err)
	}
	clk.add(599 * time.Second)
	if _, err := v.Verify(ctx, sign(t, k, claimsFor(f, nil))); err != nil {
		t.Fatal(err)
	}
	if f.jwksHits.Load() != 1 {
		t.Fatalf("jwks hits %d", f.jwksHits.Load())
	}
	clk.add(2 * time.Second)
	if _, err := v.Verify(ctx, sign(t, k, claimsFor(f, nil))); err != nil {
		t.Fatal(err)
	}
	if f.jwksHits.Load() != 2 || f.discHits.Load() != 1 {
		t.Fatalf("jwks %d discovery %d", f.jwksHits.Load(), f.discHits.Load())
	}
}

// Without configured algorithms, the issuer's published ones decide.
func TestVerifyIssuerAlgorithmsByDefault(t *testing.T) {
	v, f, _, _ := setup(t)
	f.set(func(f *fakeIssuer) { f.algs = []string{"EdDSA"} })
	ed := newKey(t, "ed", jose.EdDSA)
	f.publish(ed)
	if _, err := v.Verify(context.Background(), sign(t, ed, claimsFor(f, nil))); err != nil {
		t.Fatal(err)
	}
	rs := newKey(t, "rs", jose.RS256)
	f.publish(rs)
	_, err := v.Verify(context.Background(), sign(t, rs, claimsFor(f, nil)))
	wantCode(t, err, ErrBadSignature, 401)
}

// Claims are read case-sensitively: "SUB" is not sub, "Client_ID" is not
// client_id, "EXP" is not exp.
func TestVerifyClaimsCaseSensitive(t *testing.T) {
	ctx := context.Background()
	v, f, k, _ := setup(t)
	for name, c := range map[string]struct {
		mod  func(map[string]any)
		want *Error
	}{
		"SUB":       {func(m map[string]any) { m["SUB"] = m["sub"]; delete(m, "sub") }, ErrTokenMalformed},
		"Client_ID": {func(m map[string]any) { m["Client_ID"] = m["client_id"]; delete(m, "client_id") }, ErrWrongClient},
		"EXP":       {func(m map[string]any) { m["EXP"] = m["exp"]; delete(m, "exp") }, ErrTokenMalformed},
		"ISS":       {func(m map[string]any) { m["ISS"] = m["iss"]; delete(m, "iss") }, ErrWrongIssuer},
		"exp text":  {func(m map[string]any) { m["exp"] = "tomorrow" }, ErrTokenMalformed},
	} {
		claims := stagingAccess(f)
		c.mod(claims)
		_, err := v.Verify(ctx, sign(t, k, claims))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: want %s, got %v", name, c.want.Code, err)
		}
	}
}

// Discovery and keys are never fetched over a redirect, nor from a plain
// http keys address.
func TestVerifyNoRedirectsNoPlainHTTP(t *testing.T) {
	ctx := context.Background()
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetHits.Add(1) }))
	t.Cleanup(target.Close)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redir.Close)
	v, err := NewVerifier(VerifierConfig{Issuers: []string{redir.URL}, ClientIDs: []string{"web-client"}})
	if err != nil {
		t.Fatal(err)
	}
	k := newKey(t, "k1", jose.RS256)
	_, err = v.Verify(ctx, sign(t, k, map[string]any{"iss": redir.URL, "sub": "u", "client_id": "web-client", "exp": time.Now().Add(time.Minute).Unix()}))
	wantCode(t, err, ErrKeysUnavailable, 503)
	if targetHits.Load() != 0 {
		t.Fatal("followed the redirect")
	}
	// a keys address over plain http (not localhost) is refused
	v2, f, k2, _ := setup(t)
	f.set(func(f *fakeIssuer) { f.jwksOverride = "http://keys.example/jwks" })
	_, err = v2.Verify(ctx, sign(t, k2, claimsFor(f, nil)))
	wantCode(t, err, ErrKeysUnavailable, 503)
}

// While one caller waits for a slow issuer, another caller whose context
// ends stops at once: no lock is held during the fetch.
func TestVerifyNoLockDuringFetch(t *testing.T) {
	v, f, k, _ := setup(t, func(c *VerifierConfig) { c.FetchTimeout = 5 * time.Second })
	release := make(chan struct{})
	f.set(func(f *fakeIssuer) { f.hold = release })
	tok := sign(t, k, claimsFor(f, nil))
	first := make(chan error, 1)
	go func() { _, err := v.Verify(context.Background(), tok); first <- err }()
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := v.Verify(ctx, tok)
	wantCode(t, err, ErrKeysUnavailable, 503)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the second caller waited %v", d)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if f.discHits.Load() != 1 {
		t.Fatalf("discovery hits %d, want 1 (shared)", f.discHits.Load())
	}
}

// A caller that gives up does not burn the unknown-key cooldown: the fetch
// it started still completes, and the next caller finds the new key.
func TestVerifyCancelledCallerKeepsTheFetch(t *testing.T) {
	ctx := context.Background()
	v, f, k1, _ := setup(t)
	if _, err := v.Verify(ctx, sign(t, k1, claimsFor(f, nil))); err != nil {
		t.Fatal(err)
	}
	k2 := newKey(t, "k2", jose.RS256)
	f.publish(k2)
	release := make(chan struct{})
	f.set(func(f *fakeIssuer) { f.hold = release })
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	_, err := v.Verify(short, sign(t, k2, claimsFor(f, nil)))
	wantCode(t, err, ErrKeysUnavailable, 503)
	close(release)
	time.Sleep(50 * time.Millisecond)
	if _, err := v.Verify(ctx, sign(t, k2, claimsFor(f, nil))); err != nil {
		t.Fatalf("the new key was lost with the cancelled caller: %v", err)
	}
}
