package qauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// AppPasskeys adds a passkey on your app's own page when your server keeps
// the tokens (EXA-630). Your page calls your own endpoints; they call these
// with the person's token and pass the creation options and the browser's
// answer through (navigator.credentials.create runs on your page). Origin
// is your page's origin: the browser's answer must name it, and it must be
// one of the tenant's related origins (its apps' redirect origins).
//
// Begin answers a *StepNeededError (403 STEP_NEEDED, with the ways this
// person can confirm with) when their sign-in isn't fresh by the app's
// passkeyAddFreshness: confirm inline with Step and VerifyStep, then Begin
// again.
type AppPasskeys struct{ t *transport }

// Passkeys adds passkeys from the app's page (see AppPasskeys).
func (a *Account) Passkeys() *AppPasskeys { return &AppPasskeys{t: a.t} }

// PasskeyBegin is a ceremony begun: the creation options for the tenant's
// passkey home (RPID), single use, 5 minutes.
type PasskeyBegin struct {
	Ceremony  string          `json:"ceremony"`
	Options   json.RawMessage `json:"options,omitempty"`
	RPID      string          `json:"rpId"`
	ExpiresAt time.Time       `json:"expiresAt"`
	// PopupURL: a pop-up ceremony (browsers without related origins): open it.
	PopupURL string `json:"popupUrl,omitempty"`
}

// AddedPasskey is the new passkey.
type AddedPasskey struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	RPID string `json:"rpId"`
}

// PasskeyStepStart is the inline check under way.
type PasskeyStepStart struct {
	Way       string          `json:"way"`
	Step      string          `json:"step,omitempty"`
	Options   json.RawMessage `json:"options,omitempty"`
	SentTo    string          `json:"sentTo,omitempty"`
	ExpiresAt *time.Time      `json:"expiresAt,omitempty"`
}

// The ways to confirm inline (StepNeededError.Ways; the way of Step and
// VerifyStep).
const (
	StepWayPasskey = "passkey" // an existing passkey (WebAuthn get; Step answers the options)
	StepWayCode    = "code"    // a code from the authenticator app
	StepWaySMS     = "sms"     // a code texted to the verified phone
	StepWayEmail   = "email"   // a code by email (only for someone with no second step)
)

// StepNeededError is Begin's 403 STEP_NEEDED: the person's sign-in isn't
// fresh by the app's passkeyAddFreshness. Ask them one of Ways on your page
// (Step, then VerifyStep), then Begin again. No Ways: they have nothing to
// confirm with inline; send them to sign in again with their second step.
//
// It wraps the *Error, so errors.As(err, &qerr) with a *Error and
// errors.Is(err, ErrStepNeeded) work too.
type StepNeededError struct {
	// Ways: "passkey", "code", "sms", "email" (StepWay*), best first.
	Ways []string `json:"ways"`
	// PasskeyAddFreshness is the app's setting: "session" or minutes (a JSON
	// string or number).
	PasskeyAddFreshness json.RawMessage `json:"passkeyAddFreshness,omitempty"`
	// Refusal is qAuth's answer (Status 403, Code STEP_NEEDED, Message).
	Refusal *Error `json:"-"`
}

// Error returns the refusal's text.
func (e *StepNeededError) Error() string { return e.Refusal.Error() }

// Unwrap returns the *Error.
func (e *StepNeededError) Unwrap() error { return e.Refusal }

// stepNeeded turns a STEP_NEEDED *Error into a *StepNeededError.
func stepNeeded(err error) error {
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeStepNeeded {
		return err
	}
	out := &StepNeededError{Refusal: e}
	if len(e.Data) > 0 {
		if jerr := json.Unmarshal(e.Data, out); jerr != nil {
			return &Error{Status: e.Status, Code: CodeBadResponse, Message: "qAuth's STEP_NEEDED answer has an unexpected shape.", RequestID: e.RequestID, Data: e.Data, Err: jerr}
		}
	}
	if out.Ways == nil {
		out.Ways = []string{}
	}
	return out
}

// Begin starts adding a passkey (popup: qAuth's pop-up runs the ceremony).
// A sign-in that isn't fresh enough answers a *StepNeededError.
func (p *AppPasskeys) Begin(ctx context.Context, origin string, popup bool) (*PasskeyBegin, error) {
	var out PasskeyBegin
	err := p.t.call(ctx, http.MethodPost, "/v1/me/passkeys/begin", nil, map[string]any{"origin": origin, "popup": popup}, &out)
	return ret(&out, stepNeeded(err))
}

// Finish saves the passkey from the browser's credential (as JSON).
func (p *AppPasskeys) Finish(ctx context.Context, origin, ceremony string, credential json.RawMessage, name string) (*AddedPasskey, error) {
	var out AddedPasskey
	body := map[string]any{"origin": origin, "ceremony": ceremony, "credential": credential, "name": name}
	return ret(&out, p.t.call(ctx, http.MethodPost, "/v1/me/passkeys/finish", nil, body, &out))
}

// Step starts the inline check after a *StepNeededError: way is one of its
// Ways (StepWayPasskey, StepWayCode, StepWaySMS, StepWayEmail). A passkey
// answers WebAuthn request options (for navigator.credentials.get) and a
// Step id; sms and email send a code and answer a Step id and SentTo; code
// (the authenticator app) starts nothing.
func (p *AppPasskeys) Step(ctx context.Context, origin, way string) (*PasskeyStepStart, error) {
	var out PasskeyStepStart
	return ret(&out, p.t.call(ctx, http.MethodPost, "/v1/me/passkeys/step", nil, map[string]any{"origin": origin, "way": way}, &out))
}

// VerifyStep answers it: a passkey's assertion as JSON (answer, with step),
// or a code (with step for sms and email; none for the authenticator app).
// On success the token's own sign-in counts as having passed a second step
// now: Begin again. Wrong answers count against the account's lockout.
func (p *AppPasskeys) VerifyStep(ctx context.Context, origin, way, step string, answer json.RawMessage, code string) error {
	body := map[string]any{"origin": origin, "way": way, "step": step, "code": code}
	if len(answer) > 0 {
		body["answer"] = answer
	}
	return p.t.call(ctx, http.MethodPost, "/v1/me/passkeys/step/verify", nil, body, nil)
}
