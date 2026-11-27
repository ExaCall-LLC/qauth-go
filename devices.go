package qauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

// Sessions and devices (qAuth 2026-11-25): My account › Devices, pairing
// codes, approving a TV's code with the person's own token, organization
// admins ending a member's devices, and an organization's stricter session
// settings per app. The device side (a TV asking for a code) is standard
// OAuth (RFC 8628) on the issuer: POST /oauth/v2/device_authorization,
// then poll /oauth/v2/token; or POST /oauth/v2/device_pair with a pairing
// code (see the docs page sessions-and-devices).

// Device is one signed-in device (one app session).
type Device struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Type: tv | phone | computer | other.
	Type string `json:"type"`
	// Kind: signin | code (a TV code) | pairing | phone (a computer signed in with a phone).
	Kind       string    `json:"kind"`
	Shared     bool      `json:"shared"`
	AppID      string    `json:"appId"`
	AppName    string    `json:"appName"`
	ClientID   string    `json:"clientId"`
	Place      string    `json:"place"`
	StartedAt  time.Time `json:"startedAt"`
	LastActive time.Time `json:"lastActiveAt"`
	// Current: the device the call came from.
	Current bool `json:"current"`
}

// DeviceCount is how many devices are in use against a limit (Type "" =
// all devices together; Limit 0 = none).
type DeviceCount struct {
	Type  string `json:"type"`
	InUse int    `json:"inUse"`
	Limit int    `json:"limit"`
}

// DeviceList is the person's devices, with the counts for one app.
type DeviceList struct {
	Devices []Device      `json:"devices"`
	AppID   string        `json:"appId,omitempty"`
	Counts  []DeviceCount `json:"counts,omitempty"`
	Apps    []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Pairing bool   `json:"pairing"`
	} `json:"apps"`
}

// PairingCode is a new pairing code, shown once.
type PairingCode struct {
	Code      string    `json:"code"`
	AppID     string    `json:"appId"`
	AppName   string    `json:"appName"`
	ExpiresAt time.Time `json:"expiresAt"`
	// URL is the app's device sign-in address (never the code).
	URL string `json:"url"`
}

// WaitingDevice is a device waiting for approval, as the person sees it.
type WaitingDevice struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	UserCode   string    `json:"userCode"`
	DeviceName string    `json:"deviceName"`
	DeviceType string    `json:"deviceType"`
	Shared     bool      `json:"shared"`
	AppID      string    `json:"appId"`
	AppName    string    `json:"appName"`
	Place      string    `json:"place"`
	AskedAt    time.Time `json:"askedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	SecondStep bool      `json:"secondStep"`
	// Choices: number matching (the device shows one; the person picks it).
	Choices []int `json:"choices,omitempty"`
	// OtherNetwork: the device is on another network than the approver.
	OtherNetwork          bool   `json:"otherNetwork"`
	ApproverPlace         string `json:"approverPlace,omitempty"`
	RefusedOnOtherNetwork bool   `json:"refusedOnOtherNetwork,omitempty"`
	Max                   int    `json:"max"`
	TypeMax               int    `json:"typeMax"`
	InUse                 int    `json:"inUse"`
	TypeInUse             int    `json:"typeInUse"`
}

// Devices are the person's signed-in devices.
type Devices struct{ t *transport }

// List lists the person's devices. app names the app whose counts to show
// (""), session your ID token's sid: access tokens carry none, so without
// it no device is marked Current.
func (x *Devices) List(ctx context.Context, app, session string) (*DeviceList, error) {
	var out DeviceList
	return ret(&out, x.t.call(ctx, http.MethodGet, "/v1/me/devices", url.Values{"app": {app}, "session": {session}}, nil, &out))
}

// Update renames a device ("" keeps the name) and marks it shared or not
// (nil keeps it).
func (x *Devices) Update(ctx context.Context, deviceID, name string, shared *bool) (*Device, error) {
	var out Device
	return ret(&out, x.t.call(ctx, http.MethodPut, "/v1/me/devices/"+seg(deviceID), nil, map[string]any{"name": name, "shared": shared}, &out))
}

// SignOut signs one device out.
func (x *Devices) SignOut(ctx context.Context, deviceID string) error {
	return x.t.call(ctx, http.MethodDelete, "/v1/me/devices/"+seg(deviceID), nil, nil, nil)
}

// SignOutAll signs out every device of a type ("" = every type) of an app
// ("" = every app). keep names your own device (your ID token's sid, or
// its device id) so it stays signed in; "" answers 400 (qAuth never
// guesses which device is yours: use SignOutAllIncludingCurrent). It
// answers how many.
func (x *Devices) SignOutAll(ctx context.Context, typ, app, keep string) (int, error) {
	return x.signOutAll(ctx, typ, app, keep, false)
}

// SignOutAllIncludingCurrent is SignOutAll that signs the calling device
// out too.
func (x *Devices) SignOutAllIncludingCurrent(ctx context.Context, typ, app string) (int, error) {
	return x.signOutAll(ctx, typ, app, "", true)
}

func (x *Devices) signOutAll(ctx context.Context, typ, app, keep string, all bool) (int, error) {
	var out struct {
		Count int `json:"count"`
	}
	q := url.Values{"type": {typ}, "app": {app}, "keep": {keep}}
	if all {
		q.Set("includeCurrent", "true")
	}
	err := x.t.call(ctx, http.MethodDelete, "/v1/me/devices", q, nil, &out)
	return out.Count, err
}

// PairingCode makes a single-use code to add a device to the app. It
// needs a recent sign-in to your app (403 FRESH_SIGN_IN_REQUIRED);
// clientID names your OAuth client when the token doesn't ("").
func (x *Devices) PairingCode(ctx context.Context, appID, clientID string) (*PairingCode, error) {
	var out PairingCode
	return ret(&out, x.t.call(ctx, http.MethodPost, "/v1/me/pairing-codes", url.Values{"client": {clientID}}, map[string]string{"appId": appID}, &out))
}

// ApproveOptions: Number is the one the person picked from Lookup's Choices;
// ConfirmPlace approves a device on another network (409 CONFIRM_PLACE
// without it); SignOut are devices to sign out first at the limit;
// ClientID names your OAuth client when the token doesn't.
type ApproveOptions struct {
	Number       int
	ConfirmPlace bool
	SignOut      []string
	ClientID     string
}

// Lookup is the device waiting for a code (wrong codes count).
func (x *Devices) Lookup(ctx context.Context, code string) (*WaitingDevice, error) {
	var out WaitingDevice
	return ret(&out, x.t.call(ctx, http.MethodGet, "/v1/me/device-approvals/"+seg(code), nil, nil, &out))
}

// Approve signs the waiting device in with its own session. A wrong
// number refuses the device for good. At the app's limit it fails with
// 409 SESSION_LIMIT; pass the devices the person picked in SignOut.
func (x *Devices) Approve(ctx context.Context, code string, o ApproveOptions) error {
	return x.t.call(ctx, http.MethodPost, "/v1/me/device-approvals/"+seg(code), url.Values{"client": {o.ClientID}},
		map[string]any{"decision": "approve", "number": o.Number, "confirmPlace": o.ConfirmPlace, "signOut": o.SignOut}, nil)
}

// Deny refuses the waiting device.
func (x *Devices) Deny(ctx context.Context, code string) error {
	return x.t.call(ctx, http.MethodPost, "/v1/me/device-approvals/"+seg(code), nil, map[string]string{"decision": "deny"}, nil)
}

// Devices lists a member's devices in the apps the organization uses (admins).
func (x *Members) Devices(ctx context.Context, userID string) (*Page[Device], error) {
	return list[Device](ctx, x.o.t, x.o.p("/members/"+seg(userID)+"/devices"), nil)
}

// EndDevice ends one of a member's devices ("" = all of them in the apps
// the organization uses). Admins can't rename or add devices for them.
func (x *Members) EndDevice(ctx context.Context, userID, deviceID string) (int, error) {
	path := "/members/" + seg(userID) + "/devices"
	if deviceID != "" {
		path += "/" + seg(deviceID)
	}
	var out struct {
		Count int `json:"count"`
	}
	err := x.o.t.call(ctx, http.MethodDelete, x.o.p(path), nil, nil, &out)
	return out.Count, err
}

// SessionSettings are an app's session limits and device sign-in settings.
type SessionSettings struct {
	MaxSessions        int            `json:"maxSessions"`
	PerType            map[string]int `json:"perType"`
	AtLimit            string         `json:"atLimit"`
	Replace            string         `json:"replace"`
	DeviceSignIn       bool           `json:"deviceSignIn"`
	DeviceCodeMinutes  int            `json:"deviceCodeMinutes"`
	Pairing            bool           `json:"pairing"`
	PairingMinutes     int            `json:"pairingMinutes"`
	PairingLength      int            `json:"pairingLength"`
	WrongTries         int            `json:"wrongTries"`
	WrongWindowMinutes int            `json:"wrongWindowMinutes"`
	SecondStep         bool           `json:"secondStep"`
	PhoneSignIn        bool           `json:"phoneSignIn"`
	PhoneQRSeconds     int            `json:"phoneQrSeconds"`
	SharedIdleMinutes  int            `json:"sharedIdleMinutes"`
	KioskQR            bool           `json:"kioskQr"`
	KioskType          string         `json:"kioskType"`
	OrgDeviceLimit     int            `json:"orgDeviceLimit"`
	SkipNumberMatch    bool           `json:"skipNumberMatch"`
	PhonePlaceMismatch string         `json:"phonePlaceMismatch"`
	FreshMinutes       int            `json:"freshMinutes"`
	OwnAppOnly         bool           `json:"ownAppOnly"`
	SkipNewDeviceEmail bool           `json:"skipNewDeviceEmail"`
	SkipReplacedEmail  bool           `json:"skipReplacedEmail"`
	PairingAppTries    int            `json:"pairingAppTries"`
	// IdleByType: -1 never idle (TVs by default), 0 the usual rule, or minutes.
	IdleByType map[string]int `json:"idleByType"`
	// The sign-in page: SigninForm email_first (default) | one_screen;
	// no "Choose an account" list / last email / passkey autofill; "Email me
	// a code"; emails at verified domains not sent to company sign-in.
	SigninForm          string `json:"signinForm"`
	SkipChooser         bool   `json:"skipChooser"`
	SkipLastEmail       bool   `json:"skipLastEmail"`
	SkipPasskeyAutofill bool   `json:"skipPasskeyAutofill"`
	EmailCodeSignIn     bool   `json:"emailCodeSignIn"`
	SkipCompanyByDomain bool   `json:"skipCompanyByDomain"`
	// ReverifyOnReuse: when a reused shared sign-in asks a quick check:
	// minutes (a JSON number), "always", "never" or "default".
	ReverifyOnReuse json.RawMessage `json:"reverifyOnReuse,omitempty"`
	// EmbedPasskeyPage: the app's pages may embed qAuth's add-a-passkey
	// page (/ui/passkeys/add; off by default).
	EmbedPasskeyPage bool `json:"embedPasskeyPage"`
	// EmbedPasskeyDevOrigins: localhost origins may embed it too (development).
	EmbedPasskeyDevOrigins bool `json:"embedPasskeyDevOrigins"`
}

// OrgSessionSettings are an organization's stricter settings for one app
// (nil = the app's).
type OrgSessionSettings struct {
	MaxSessions       *int           `json:"maxSessions,omitempty"`
	PerType           map[string]int `json:"perType,omitempty"`
	AtLimit           *string        `json:"atLimit,omitempty"`
	Replace           *string        `json:"replace,omitempty"`
	DeviceSignIn      *bool          `json:"deviceSignIn,omitempty"`
	DeviceCodeMinutes *int           `json:"deviceCodeMinutes,omitempty"`
	Pairing           *bool          `json:"pairing,omitempty"`
	PairingMinutes    *int           `json:"pairingMinutes,omitempty"`
	WrongTries        *int           `json:"wrongTries,omitempty"`
	SecondStep        *bool          `json:"secondStep,omitempty"`
	PhoneSignIn       *bool          `json:"phoneSignIn,omitempty"`
	SharedIdleMinutes *int           `json:"sharedIdleMinutes,omitempty"`
	KioskQR           *bool          `json:"kioskQr,omitempty"`
	NumberMatch       *bool          `json:"numberMatch,omitempty"`
	FreshMinutes      *int           `json:"freshMinutes,omitempty"`
	IdleByType        map[string]int `json:"idleByType,omitempty"`
	// Sign-in page, only stricter: SigninForm only "email_first",
	// SkipChooser / SkipLastEmail only true, EmailCodeSignIn only false.
	SigninForm      *string `json:"signinForm,omitempty"`
	SkipChooser     *bool   `json:"skipChooser,omitempty"`
	SkipLastEmail   *bool   `json:"skipLastEmail,omitempty"`
	EmailCodeSignIn *bool   `json:"emailCodeSignIn,omitempty"`
	// ReverifyOnReuse: "always", or fewer minutes (a JSON number) than the app's rule.
	ReverifyOnReuse json.RawMessage `json:"reverifyOnReuse,omitempty"`
}

// OrgSessionSettingsView is an organization's view of one app's settings.
type OrgSessionSettingsView struct {
	AppID     string             `json:"appId"`
	AppName   string             `json:"appName"`
	App       SessionSettings    `json:"app"`
	Override  OrgSessionSettings `json:"override"`
	Effective SessionSettings    `json:"effective"`
}

// SessionSettings reads the organization's settings for one app.
func (o *OrgClient) SessionSettings(ctx context.Context, appID string) (*OrgSessionSettingsView, error) {
	var out OrgSessionSettingsView
	return ret(&out, o.t.call(ctx, http.MethodGet, o.p("/apps/"+seg(appID)+"/session-settings"), nil, nil, &out))
}

// SetSessionSettings makes one app's settings stricter for the
// organization's people (anything looser is refused: 422). An empty
// override goes back to the app's.
func (o *OrgClient) SetSessionSettings(ctx context.Context, appID string, s OrgSessionSettings) (*OrgSessionSettingsView, error) {
	var out OrgSessionSettingsView
	return ret(&out, o.t.call(ctx, http.MethodPut, o.p("/apps/"+seg(appID)+"/session-settings"), nil, s, &out))
}
