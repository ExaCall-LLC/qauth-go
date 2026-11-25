package qauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// Person is the signed-in person (their access token). Every call is that
// person acting, with exactly the rights they have.
type Person struct {
	c     *Client
	t     *transport
	token string

	// Tokens are the person's personal access tokens.
	Tokens *PersonalTokens
	// Verifications confirm a sensitive action with a one-time code.
	Verifications *Verifications
	// Account is the person's own account: password, factors, sessions.
	Account *Account
}

func newPerson(c *Client, token string) *Person {
	t := c.bearer(token)
	acc := &Account{t: t, Sessions: &Sessions{t: t}, Devices: &Devices{t: t}, Authenticator: &Authenticator{t: t}, Phone: &Phone{t: t}}
	return &Person{c: c, t: t, token: token, Tokens: &PersonalTokens{t: t}, Verifications: &Verifications{t: t}, Account: acc}
}

// Profile answers who the person is, and their organizations with their
// role in each.
func (p *Person) Profile(ctx context.Context) (*Profile, error) {
	var out Profile
	return ret(&out, p.t.call(ctx, http.MethodGet, "/v1/me", nil, nil, &out))
}

// Orgs lists the person's organizations with their role in each.
func (p *Person) Orgs(ctx context.Context) (*Page[MyOrg], error) {
	return list[MyOrg](ctx, p.t, "/v1/me/orgs", nil)
}

// Permissions answers the person's roles and permissions in one app inside
// one organization (cached like Client.Permissions).
func (p *Person) Permissions(ctx context.Context, app, org string) (*Effective, error) {
	return p.c.Permissions(ctx, Token(p.token), app, org)
}

// Can reports whether the person holds a permission key (see Client.Can).
func (p *Person) Can(ctx context.Context, app, org, permission string) (bool, error) {
	return p.c.Can(ctx, Token(p.token), app, org, permission)
}

// Org is one of the person's organizations. Only members reach it: for
// anyone else qAuth answers not found.
func (p *Person) Org(orgID string) *OrgClient { return newOrgClient(p.t, orgID) }

// PersonalTokens are personal access tokens: for scripts and tools acting as
// the person in one organization, with a subset of their own permissions.
type PersonalTokens struct{ t *transport }

// List lists the person's tokens (never the secrets).
func (x *PersonalTokens) List(ctx context.Context) (*Page[APIKey], error) {
	return list[APIKey](ctx, x.t, "/v1/me/tokens", nil)
}

// Choices answers, per API, the permissions the person can put in a token
// for this organization.
func (x *PersonalTokens) Choices(ctx context.Context, orgID string) (*Page[TokenChoice], error) {
	return list[TokenChoice](ctx, x.t, "/v1/me/token-choices", url.Values{"org": {orgID}})
}

// Create makes a token. The secret is shown ONCE.
func (x *PersonalTokens) Create(ctx context.Context, tk NewPersonalToken) (*MintedAPIKey, error) {
	var out MintedAPIKey
	return ret(&out, x.t.call(ctx, http.MethodPost, "/v1/me/tokens", nil, tk, &out))
}

// Revoke ends one of the person's tokens at once.
func (x *PersonalTokens) Revoke(ctx context.Context, tokenID string) error {
	return x.t.call(ctx, http.MethodDelete, "/v1/me/tokens/"+seg(tokenID), nil, nil, nil)
}

// Verifications confirm a sensitive action (a transfer, a change of email)
// with a one-time code sent to the person's OWN phone or email, or from
// their authenticator app. Your backend calls Consume with exactly what it
// is about to do before acting; it answers yes once.
type Verifications struct{ t *transport }

// Start sends a code for an action. template is the template's id or name.
func (x *Verifications) Start(ctx context.Context, template string, variables map[string]string, o VerifyOptions) (*StartedVerification, error) {
	if variables == nil {
		variables = map[string]string{}
	}
	body := map[string]any{"template": template, "variables": variables}
	if o.Channel != "" {
		body["channel"] = o.Channel
	}
	if o.Locale != "" {
		body["locale"] = o.Locale
	}
	var out StartedVerification
	return ret(&out, x.t.call(ctx, http.MethodPost, "/v1/verifications", nil, body, &out))
}

// Resend sends the code again, or by another of the person's channels.
func (x *Verifications) Resend(ctx context.Context, requestID string, o VerifyOptions) (*StartedVerification, error) {
	var out StartedVerification
	return ret(&out, x.t.call(ctx, http.MethodPost, "/v1/verifications/"+seg(requestID)+"/resend", nil, o, &out))
}

// Check checks the code the person typed.
func (x *Verifications) Check(ctx context.Context, requestID, code string) (*VerificationCheck, error) {
	var out VerificationCheck
	return ret(&out, x.t.call(ctx, http.MethodPost, "/v1/verifications/"+seg(requestID)+"/check", nil, map[string]string{"code": code}, &out))
}

// Consume is your backend's call before acting: a 409 *Error unless this
// person verified this template for exactly these values, recently, and it
// was never used.
func (x *Verifications) Consume(ctx context.Context, requestID, template string, variables map[string]string) (*ConsumedVerification, error) {
	if variables == nil {
		variables = map[string]string{}
	}
	var out ConsumedVerification
	return ret(&out, x.t.call(ctx, http.MethodPost, "/v1/verifications/"+seg(requestID)+"/consume", nil,
		map[string]any{"template": template, "variables": variables}, &out))
}

// Account is the person's own account. Removing a factor or making new
// recovery codes needs a fresh Proof; wrong proofs count toward the
// account's lockout.
type Account struct {
	t *transport
	// Sessions are the person's sign-in sessions.
	Sessions *Sessions
	// Devices are where the person is signed in (My account › Devices),
	// pairing codes and TV approvals.
	Devices *Devices
	// Authenticator is the person's authenticator app.
	Authenticator *Authenticator
	// Phone is the person's verified phone.
	Phone *Phone
}

// Security answers the person's account page.
func (a *Account) Security(ctx context.Context) (*MySecurity, error) {
	var out MySecurity
	return ret(&out, a.t.call(ctx, http.MethodGet, "/v1/me/security", nil, nil, &out))
}

// ChangePassword changes the person's password (422 when current is wrong).
func (a *Account) ChangePassword(ctx context.Context, current, next string) error {
	return a.t.call(ctx, http.MethodPut, "/v1/me/password", nil, map[string]string{"current": current, "new": next}, nil)
}

// RecoveryCodes makes ten new single-use codes, shown once (the old ones
// stop working). A proof is needed when codes already exist; pass nil
// otherwise.
func (a *Account) RecoveryCodes(ctx context.Context, proof *Proof) ([]string, error) {
	var body any = map[string]any{}
	if proof != nil {
		body = proof
	}
	var out struct {
		Codes []string `json:"codes"`
	}
	return out.Codes, a.t.call(ctx, http.MethodPost, "/v1/me/recovery-codes", nil, body, &out)
}

// RemovePasskey removes one of the person's passkeys (listed in Security).
func (a *Account) RemovePasskey(ctx context.Context, passkeyID string, proof Proof) error {
	return a.t.call(ctx, http.MethodDelete, "/v1/me/passkeys/"+seg(passkeyID), nil, proof, nil)
}

// LastStepUp answers the person's latest step-up for your OAuth client, or
// nil when there is none. Accept it only if IsFreshStepUp.
func (a *Account) LastStepUp(ctx context.Context, clientID string) (*StepUp, error) {
	var out StepUp
	err := a.t.call(ctx, http.MethodGet, "/v1/me/step-up", url.Values{"client": {clientID}}, nil, &out)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ret(&out, nil)
}

// Authenticator is the person's authenticator app.
type Authenticator struct{ t *transport }

// Start answers the otpauth:// address (show it as a QR code) and its secret.
func (x *Authenticator) Start(ctx context.Context) (uri, secret string, err error) {
	var out struct {
		URI    string `json:"uri"`
		Secret string `json:"secret"`
	}
	err = x.t.call(ctx, http.MethodPost, "/v1/me/authenticator", nil, nil, &out)
	return out.URI, out.Secret, err
}

// Verify finishes adding the authenticator with a code from it.
func (x *Authenticator) Verify(ctx context.Context, code string) error {
	return x.t.call(ctx, http.MethodPost, "/v1/me/authenticator/verify", nil, map[string]string{"code": code}, nil)
}

// Remove removes the authenticator (needs a proof).
func (x *Authenticator) Remove(ctx context.Context, proof Proof) error {
	return x.t.call(ctx, http.MethodDelete, "/v1/me/authenticator", nil, proof, nil)
}

// Phone is the person's verified phone.
type Phone struct{ t *transport }

// Add sends a code to the number and answers where it went (masked); the
// number is saved once Verify gets the right code.
func (x *Phone) Add(ctx context.Context, phone string) (codeSentTo string, err error) {
	var out struct {
		CodeSentTo string `json:"codeSentTo"`
	}
	err = x.t.call(ctx, http.MethodPost, "/v1/me/phone", nil, map[string]string{"phone": phone}, &out)
	return out.CodeSentTo, err
}

// Verify saves the phone with the code sent to it.
func (x *Phone) Verify(ctx context.Context, code string) error {
	return x.t.call(ctx, http.MethodPost, "/v1/me/phone/verify", nil, map[string]string{"code": code}, nil)
}

// Remove removes the phone (needs a proof).
func (x *Phone) Remove(ctx context.Context, proof Proof) error {
	return x.t.call(ctx, http.MethodDelete, "/v1/me/phone", nil, proof, nil)
}

// Sessions are the person's sign-in sessions.
type Sessions struct{ t *transport }

// List lists the person's sessions.
func (x *Sessions) List(ctx context.Context) (*Page[SessionInfo], error) {
	return list[SessionInfo](ctx, x.t, "/v1/me/sessions", nil)
}

// End ends one of the person's sessions.
func (x *Sessions) End(ctx context.Context, sessionID string) error {
	return x.t.call(ctx, http.MethodDelete, "/v1/me/sessions/"+seg(sessionID), nil, nil, nil)
}

// EndAll signs the person out everywhere, here too: their tokens stop
// working at once. It answers how many sessions ended.
func (x *Sessions) EndAll(ctx context.Context) (int, error) {
	var out struct {
		Count int `json:"count"`
	}
	err := x.t.call(ctx, http.MethodDelete, "/v1/me/sessions", nil, nil, &out)
	return out.Count, err
}

// State answers the session's sign-out rules and time left (sessionID = the
// ID token's sid). With single sign-on several apps share one sid, each with
// its own rules: pass your OAuth clientID ("" when your token names it).
func (x *Sessions) State(ctx context.Context, sessionID, clientID string) (*SessionState, error) {
	var out SessionState
	return ret(&out, x.t.call(ctx, http.MethodGet, "/v1/me/sessions/"+seg(sessionID)+"/state", url.Values{"client": {clientID}}, nil, &out))
}

// Activity says "still here": it resets the idle timer of YOUR app's
// session and answers its new state. Send it at most once a minute.
func (x *Sessions) Activity(ctx context.Context, sessionID, clientID string) (*SessionState, error) {
	var out SessionState
	return ret(&out, x.t.call(ctx, http.MethodPost, "/v1/me/sessions/"+seg(sessionID)+"/activity", url.Values{"client": {clientID}}, nil, &out))
}

// StepUpParams are the extra authorize parameters that make qAuth ask for a
// fresh second step (the app's Step-up switch must be on). Note when you
// sent the person, then check Account.LastStepUp with the NEW tokens and
// IsFreshStepUp.
var StepUpParams = map[string]string{"max_age": "0"}

// IsFreshStepUp reports whether the step-up happened after startedAt and
// within the window (0 means 10 minutes). The record is per person and
// client, not per browser session: always compare with your own startedAt.
func IsFreshStepUp(record *StepUp, startedAt time.Time, within time.Duration) bool {
	if record == nil {
		return false
	}
	if within <= 0 {
		within = 10 * time.Minute
	}
	return !record.At.Before(startedAt.Add(-time.Second)) && time.Since(record.At) <= within
}

// Activity is the person's recent activity, newest first (My account ›
// Security): their sign-ins and sign-outs (device, address), refused
// sign-ins, password, second-step, passkey and token changes, and what an
// admin did to their account. Actor and Target in q are ignored.
func (a *Account) Activity(ctx context.Context, q AuditQuery) (*Page[AuditEntry], error) {
	q.Actor, q.Target = "", ""
	return list[AuditEntry](ctx, a.t, "/v1/me/activity", q.values())
}
