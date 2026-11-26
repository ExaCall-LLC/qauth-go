package qauth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
)

// OrgClient is one organization, as the caller (a person or an API key)
// sees it. Admins manage the organization; managers manage people (never
// the admin role); members read.
type OrgClient struct {
	// ID is the organization's id.
	ID string
	t  *transport

	// Members are the organization's people.
	Members *Members
	// Invitations: no account exists until the person accepts.
	Invitations *Invitations
	// Roles are the organization's own roles for one app.
	Roles *OrgRoles
	// Assignments are who holds which roles of one app.
	Assignments *Assignments
	// Domains are the organization's verified email domains.
	Domains *Domains
	// APIKeys are the organization's API keys (admins).
	APIKeys *APIKeys
	// SSO is company sign-in (admins).
	SSO *SSO
	// SubOrgs are the organization's child organizations.
	SubOrgs *SubOrgs
	// Branding is the organization's white-label sign-in look.
	Branding *OrgBranding
	// Design is the organization's sign-in page design (layout, side panel).
	Design *OrgDesign
}

func newOrgClient(t *transport, id string) *OrgClient {
	o := &OrgClient{ID: id, t: t}
	o.Members = &Members{o}
	o.Invitations = &Invitations{o}
	o.Roles = &OrgRoles{o}
	o.Assignments = &Assignments{o}
	o.Domains = &Domains{o}
	o.APIKeys = &APIKeys{o}
	o.SSO = &SSO{o}
	o.SubOrgs = &SubOrgs{o}
	o.Branding = &OrgBranding{o}
	o.Design = &OrgDesign{o}
	return o
}

func (o *OrgClient) p(rest string) string { return "/v1/orgs/" + seg(o.ID) + rest }

// Get reads the organization.
func (o *OrgClient) Get(ctx context.Context) (*Org, error) {
	var out Org
	return ret(&out, o.t.call(ctx, http.MethodGet, o.p(""), nil, nil, &out))
}

// UpdateSettings changes the organization's settings (admins).
func (o *OrgClient) UpdateSettings(ctx context.Context, s OrgSettings) (*Org, error) {
	var out Org
	return ret(&out, o.t.call(ctx, http.MethodPut, o.p("/settings"), nil, s, &out))
}

// SetSecurity requires (or stops requiring) a second sign-in step of the
// organization's people (admins).
func (o *OrgClient) SetSecurity(ctx context.Context, s OrgSecurity) (*Org, error) {
	var out Org
	return ret(&out, o.t.call(ctx, http.MethodPut, o.p("/security"), nil, s, &out))
}

// GivableRoles answers every role of the organization, with whether the
// caller may give it and why not.
func (o *OrgClient) GivableRoles(ctx context.Context) ([]GivableRole, error) {
	var out struct {
		Roles []GivableRole `json:"roles"`
	}
	return out.Roles, o.t.call(ctx, http.MethodGet, o.p("/givable-roles"), nil, nil, &out)
}

// Apps lists the apps the organization can use.
func (o *OrgClient) Apps(ctx context.Context) (*Page[App], error) {
	return list[App](ctx, o.t, o.p("/apps"), nil)
}

// Audit reads the organization's audit log, newest first (admins).
func (o *OrgClient) Audit(ctx context.Context, q AuditQuery) (*Page[AuditEntry], error) {
	return list[AuditEntry](ctx, o.t, o.p("/audit"), q.values())
}

// Members are an organization's people.
type Members struct{ o *OrgClient }

// List lists the members.
func (x *Members) List(ctx context.Context) (*Page[Member], error) {
	return list[Member](ctx, x.o.t, x.o.p("/members"), nil)
}

// Add adds a person (an existing account of the directory is reused).
func (x *Members) Add(ctx context.Context, m NewMember) (*AddedMember, error) {
	var out AddedMember
	return ret(&out, x.o.t.call(ctx, http.MethodPost, x.o.p("/members"), nil, m, &out))
}

// SetRoles replaces the person's roles in every space at once (ids from
// GivableRoles). You can't give more than you hold.
func (x *Members) SetRoles(ctx context.Context, userID string, roleIDs []string) error {
	if roleIDs == nil {
		roleIDs = []string{}
	}
	return x.o.t.call(ctx, http.MethodPut, x.o.p("/members/"+seg(userID)+"/roles"), nil, map[string]any{"roleIds": roleIDs}, nil)
}

// SetRole sets the one-word role. Prefer SetRoles.
func (x *Members) SetRole(ctx context.Context, userID string, role Role) error {
	return x.o.t.call(ctx, http.MethodPut, x.o.p("/members/"+seg(userID)), nil, map[string]any{"role": role}, nil)
}

// ResetPassword sets a new password for a member (directory password rules
// and no-escalation apply); changeRequired makes them change it at the next
// sign-in.
func (x *Members) ResetPassword(ctx context.Context, userID, password string, changeRequired bool) error {
	return x.o.t.call(ctx, http.MethodPost, x.o.p("/members/"+seg(userID)+"/reset-password"), nil,
		map[string]any{"password": password, "changeRequired": changeRequired}, nil)
}

// Remove removes the person from the organization.
func (x *Members) Remove(ctx context.Context, userID string) error {
	return x.o.t.call(ctx, http.MethodDelete, x.o.p("/members/"+seg(userID)), nil, nil, nil)
}

// Invitations are an organization's invitations. The person accepts on
// qAuth's page (with their account, or by choosing a password).
type Invitations struct{ o *OrgClient }

// List lists invitations: pending, expired, locked, revoked.
func (x *Invitations) List(ctx context.Context) (*Page[Invitation], error) {
	return list[Invitation](ctx, x.o.t, x.o.p("/invitations"), nil)
}

// Create invites a person.
func (x *Invitations) Create(ctx context.Context, i NewInvitation) (*SentInvitation, error) {
	var out SentInvitation
	return ret(&out, x.o.t.call(ctx, http.MethodPost, x.o.p("/invitations"), nil, i, &out))
}

// Resend makes a new link with 7 more days; the old link stops working.
// send=false answers the link instead of emailing it.
func (x *Invitations) Resend(ctx context.Context, invitationID string, send bool) (*SentInvitation, error) {
	var out SentInvitation
	return ret(&out, x.o.t.call(ctx, http.MethodPost, x.o.p("/invitations/"+seg(invitationID)+"/resend"), nil, map[string]bool{"send": send}, &out))
}

// Revoke revokes an invitation.
func (x *Invitations) Revoke(ctx context.Context, invitationID string) error {
	return x.o.t.call(ctx, http.MethodDelete, x.o.p("/invitations/"+seg(invitationID)), nil, nil, nil)
}

// OrgRoles are the organization's own roles for one app, built on the app's
// permissions.
type OrgRoles struct{ o *OrgClient }

// Permissions lists the app's permissions.
func (x *OrgRoles) Permissions(ctx context.Context, appID string) (*Page[Permission], error) {
	return list[Permission](ctx, x.o.t, x.o.p("/apps/"+seg(appID)+"/permissions"), nil)
}

// List lists the app's built-in roles plus the organization's own.
func (x *OrgRoles) List(ctx context.Context, appID string) (*Page[AppRole], error) {
	return list[AppRole](ctx, x.o.t, x.o.p("/apps/"+seg(appID)+"/roles"), nil)
}

// Create creates an organization role for the app.
func (x *OrgRoles) Create(ctx context.Context, appID string, r RoleSpec) (*AppRole, error) {
	var out AppRole
	return ret(&out, x.o.t.call(ctx, http.MethodPost, x.o.p("/apps/"+seg(appID)+"/roles"), nil, r, &out))
}

// Update changes one of the organization's own roles.
func (x *OrgRoles) Update(ctx context.Context, roleID string, r RoleSpec) (*AppRole, error) {
	var out AppRole
	return ret(&out, x.o.t.call(ctx, http.MethodPut, x.o.p("/roles/"+seg(roleID)), nil, r, &out))
}

// Remove removes one of the organization's own roles.
func (x *OrgRoles) Remove(ctx context.Context, roleID string) error {
	return x.o.t.call(ctx, http.MethodDelete, x.o.p("/roles/"+seg(roleID)), nil, nil, nil)
}

// Assignments are who holds which roles of one app.
type Assignments struct{ o *OrgClient }

// List lists the people and their roles of the app.
func (x *Assignments) List(ctx context.Context, appID string) (*Page[PersonRoles], error) {
	return list[PersonRoles](ctx, x.o.t, x.o.p("/app-roles"), url.Values{"app": {appID}})
}

// Set replaces a person's roles of the app.
func (x *Assignments) Set(ctx context.Context, a Assignment) error {
	if a.RoleIDs == nil {
		a.RoleIDs = []string{}
	}
	return x.o.t.call(ctx, http.MethodPut, x.o.p("/app-roles"), nil, a, nil)
}

// Domains are the organization's email domains: accounts at a verified
// domain become the organization's managed accounts.
type Domains struct{ o *OrgClient }

// List lists the domains.
func (x *Domains) List(ctx context.Context) (*Page[OrgDomain], error) {
	return list[OrgDomain](ctx, x.o.t, x.o.p("/domains"), nil)
}

// Add adds a domain and answers the TXT record to publish.
func (x *Domains) Add(ctx context.Context, domain string) (*AddedDomain, error) {
	var out AddedDomain
	return ret(&out, x.o.t.call(ctx, http.MethodPost, x.o.p("/domains"), nil, map[string]string{"domain": domain}, &out))
}

// Verify looks for the TXT record (422 while it is missing).
func (x *Domains) Verify(ctx context.Context, domainID string) (*OrgDomain, error) {
	var out OrgDomain
	return ret(&out, x.o.t.call(ctx, http.MethodPost, x.o.p("/domains/"+seg(domainID)+"/verify"), nil, nil, &out))
}

// Remove removes a domain.
func (x *Domains) Remove(ctx context.Context, domainID string) error {
	return x.o.t.call(ctx, http.MethodDelete, x.o.p("/domains/"+seg(domainID)), nil, nil, nil)
}

// APIKeys are the organization's API keys (admins).
type APIKeys struct{ o *OrgClient }

// List lists the keys (never the secrets).
func (x *APIKeys) List(ctx context.Context) (*Page[APIKey], error) {
	return list[APIKey](ctx, x.o.t, x.o.p("/api-keys"), nil)
}

// Create makes a key. The secret is shown ONCE.
func (x *APIKeys) Create(ctx context.Context, k NewAPIKey) (*MintedAPIKey, error) {
	var out MintedAPIKey
	return ret(&out, x.o.t.call(ctx, http.MethodPost, x.o.p("/api-keys"), nil, k, &out))
}

// Revoke ends a key at once.
func (x *APIKeys) Revoke(ctx context.Context, keyID string) error {
	return x.o.t.call(ctx, http.MethodDelete, x.o.p("/api-keys/"+seg(keyID)), nil, nil, nil)
}

// SSO is company sign-in (OpenID Connect: Entra ID, Google Workspace,
// Okta...) for emails at the organization's verified domains. Admins only.
type SSO struct{ o *OrgClient }

// Get answers whether company sign-in is connected, and the callback
// address to register at the provider.
func (x *SSO) Get(ctx context.Context) (*SSOState, error) {
	var out SSOState
	return ret(&out, x.o.t.call(ctx, http.MethodGet, x.o.p("/sso"), nil, nil, &out))
}

// Set connects or changes company sign-in.
func (x *SSO) Set(ctx context.Context, s SSOSpec) (*SSOState, error) {
	var out SSOState
	return ret(&out, x.o.t.call(ctx, http.MethodPut, x.o.p("/sso"), nil, s, &out))
}

// Remove disconnects company sign-in.
func (x *SSO) Remove(ctx context.Context) error {
	return x.o.t.call(ctx, http.MethodDelete, x.o.p("/sso"), nil, nil, nil)
}

// SubOrgs are an organization's direct child organizations.
type SubOrgs struct{ o *OrgClient }

// List lists the direct child organizations.
func (x *SubOrgs) List(ctx context.Context) (*Page[Org], error) {
	return list[Org](ctx, x.o.t, x.o.p("/suborgs"), nil)
}

// Create creates a direct child organization (inheriting directory and app
// access unless isolated). Its first admin may be anyone, you too: an
// existing account is added as it is; a new one is emailed (Invited) and no
// password comes back.
//
// With IdempotencyKey, a retry is safe: the same key and the same request
// within qAuth's window (24 hours by default) answer the same child, never
// a second one; another request with that key is refused (409).
func (x *SubOrgs) Create(ctx context.Context, s NewSubOrg, opts ...CreateOption) (*CreatedSubOrg, error) {
	var o createOptions
	for _, f := range opts {
		f(&o)
	}
	t := x.o.t
	if o.idempotencyKey != "" {
		t = t.withHeader("Idempotency-Key", o.idempotencyKey)
	}
	var out CreatedSubOrg
	return ret(&out, t.call(ctx, http.MethodPost, x.o.p("/suborgs"), nil, s, &out))
}

// CreateOption changes how SubOrgs.Create sends its request.
type CreateOption func(*createOptions)

type createOptions struct{ idempotencyKey string }

// IdempotencyKey sends an Idempotency-Key (1 to 255 printable characters,
// one you make per creation): a retry with the same key and request
// answers the same child.
func IdempotencyKey(key string) CreateOption {
	return func(o *createOptions) { o.idempotencyKey = key }
}

// Rename renames the organization: a direct child from its parent (with
// org.suborgs.manage, or the parent's key with qauth:org:suborgs), or the
// organization by its own admins. Unique among its siblings.
func (o *OrgClient) Rename(ctx context.Context, name string) (*Org, error) {
	var out Org
	return ret(&out, o.t.call(ctx, http.MethodPut, o.p(""), nil, map[string]string{"name": name}, &out))
}

// SetExternalID sets your own id for a direct child ("" clears it): its
// parent (org.suborgs.manage in a role of the parent, or the parent's key
// with qauth:org:suborgs) or your tenant; never the organization's own
// people. Unique in your tenant.
func (o *OrgClient) SetExternalID(ctx context.Context, externalID string) (*Org, error) {
	var out Org
	return ret(&out, o.t.call(ctx, http.MethodPut, o.p("/external-id"), nil, map[string]string{"externalId": externalID}, &out))
}

// SetLevels sets a direct child's levels in one API, from its parent: the
// same rule as creating it (each level directly below one of the parent's).
// Refused when a child of the child, or someone holding a role of a level
// taken away, would be left without it, and for the child's last level.
func (o *OrgClient) SetLevels(ctx context.Context, apiID string, levelIDs []string) (*OrgLevels, error) {
	if levelIDs == nil {
		levelIDs = []string{}
	}
	var out OrgLevels
	return ret(&out, o.t.call(ctx, http.MethodPut, o.p("/levels/"+seg(apiID)), nil, map[string][]string{"levelIds": levelIDs}, &out))
}

// Levels reads the organization's levels in each API.
func (o *OrgClient) Levels(ctx context.Context) (*OrgLevels, error) {
	var out OrgLevels
	return ret(&out, o.t.call(ctx, http.MethodGet, o.p("/levels"), nil, nil, &out))
}

// NewAdmin sets a new admin of an organization that lost its admins.
//
// Deprecated: since 0.6.0 a parent organization never manages a child's
// people; this is your tenant's (Console, or POST /tenant/orgs/{id}/new-admin).
// From an organization it answers 403.
func (o *OrgClient) NewAdmin(ctx context.Context, email string) (*NewAdminResult, error) {
	var out NewAdminResult
	return ret(&out, o.t.call(ctx, http.MethodPost, o.p("/new-admin"), nil, map[string]string{"email": email}, &out))
}

// OrgBranding is the organization's white-label sign-in look; appID ""
// means the organization's own, an app's id its override for that app.
type OrgBranding struct{ o *OrgClient }

// Get reads the look.
func (x *OrgBranding) Get(ctx context.Context, appID string) (*Branding, error) {
	var out Branding
	return ret(&out, x.o.t.call(ctx, http.MethodGet, x.o.p("/branding"), url.Values{"app": {appID}}, nil, &out))
}

// Set sets the look (people only).
func (x *OrgBranding) Set(ctx context.Context, appID string, s BrandingSpec) (*Branding, error) {
	var out Branding
	return ret(&out, x.o.t.call(ctx, http.MethodPut, x.o.p("/branding"), url.Values{"app": {appID}}, s, &out))
}

// Remove removes the override (people only).
func (x *OrgBranding) Remove(ctx context.Context, appID string) error {
	return x.o.t.call(ctx, http.MethodDelete, x.o.p("/branding"), url.Values{"app": {appID}}, nil, nil)
}

// OrgDesign is the organization's sign-in page design: the logo and
// colours with the layout, the form side's settings and the side panel.
// appID "" means the organization's own look, an app's id its look for that
// app.
type OrgDesign struct{ o *OrgClient }

// Get reads the look, what it inherits and the platform's limits.
func (x *OrgDesign) Get(ctx context.Context, appID string) (*DesignView, error) {
	var out DesignView
	return ret(&out, x.o.t.call(ctx, http.MethodGet, x.o.p("/design"), url.Values{"app": {appID}}, nil, &out))
}

// Set saves the look (people only: admins with settings rights).
func (x *OrgDesign) Set(ctx context.Context, appID string, s BrandingSpec) (*DesignView, error) {
	var out DesignView
	return ret(&out, x.o.t.call(ctx, http.MethodPut, x.o.p("/design"), url.Values{"app": {appID}}, s, &out))
}

// Reset removes the look: the organization inherits again (people only).
func (x *OrgDesign) Reset(ctx context.Context, appID string) error {
	return x.o.t.call(ctx, http.MethodDelete, x.o.p("/design"), url.Values{"app": {appID}}, nil, nil)
}

// AddPicture keeps a picture (PNG, JPEG, WebP or GIF) for the design; use
// its Hash in a panel background or an image block (people only).
func (x *OrgDesign) AddPicture(ctx context.Context, data []byte) (*DesignFile, error) {
	var out DesignFile
	body := map[string]string{"data": base64.StdEncoding.EncodeToString(data)}
	return ret(&out, x.o.t.call(ctx, http.MethodPost, x.o.p("/design/files"), nil, body, &out))
}
