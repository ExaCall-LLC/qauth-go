package qauth

import (
	"context"
	"encoding/json"
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
// Begin answers 403 STEP_NEEDED (Error.Code; the ways in StepWays) when the
// person's sign-in isn't fresh by the app's passkeyAddFreshness: confirm
// inline with Step and VerifyStep, then Begin again.
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

// Begin starts adding a passkey (popup: qAuth's pop-up runs the ceremony).
func (p *AppPasskeys) Begin(ctx context.Context, origin string, popup bool) (*PasskeyBegin, error) {
	var out PasskeyBegin
	return ret(&out, p.t.call(ctx, http.MethodPost, "/v1/me/passkeys/begin", nil, map[string]any{"origin": origin, "popup": popup}, &out))
}

// Finish saves the passkey from the browser's credential (as JSON).
func (p *AppPasskeys) Finish(ctx context.Context, origin, ceremony string, credential json.RawMessage, name string) (*AddedPasskey, error) {
	var out AddedPasskey
	body := map[string]any{"origin": origin, "ceremony": ceremony, "credential": credential, "name": name}
	return ret(&out, p.t.call(ctx, http.MethodPost, "/v1/me/passkeys/finish", nil, body, &out))
}

// Step starts the inline check: way is passkey, code (the authenticator
// app), sms or email.
func (p *AppPasskeys) Step(ctx context.Context, origin, way string) (*PasskeyStepStart, error) {
	var out PasskeyStepStart
	return ret(&out, p.t.call(ctx, http.MethodPost, "/v1/me/passkeys/step", nil, map[string]any{"origin": origin, "way": way}, &out))
}

// VerifyStep answers it: a passkey's answer (with step), or a code (with
// step for email).
func (p *AppPasskeys) VerifyStep(ctx context.Context, origin, way, step string, answer json.RawMessage, code string) error {
	body := map[string]any{"origin": origin, "way": way, "step": step, "code": code}
	if len(answer) > 0 {
		body["answer"] = answer
	}
	return p.t.call(ctx, http.MethodPost, "/v1/me/passkeys/step/verify", nil, body, nil)
}
