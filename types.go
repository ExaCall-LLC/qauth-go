package qauth

import "time"

// Pagination describes one page of a list answer.
type Pagination struct {
	Page        int  `json:"page"`
	Limit       int  `json:"limit"`
	Total       int  `json:"total"`
	TotalPages  int  `json:"total_pages"`
	HasNext     bool `json:"has_next"`
	HasPrevious bool `json:"has_previous"`
}

// Page is a list answer: the items plus paging.
type Page[T any] struct {
	Items      []T
	Pagination Pagination
}

// Role is the one-word organization role (admin, manager or member).
type Role string

// The one-word organization roles.
const (
	RoleAdmin   Role = "admin"
	RoleManager Role = "manager"
	RoleMember  Role = "member"
)

// MyOrg is one of the person's organizations, with their role in it.
type MyOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role Role   `json:"role"`
}

// Profile is the signed-in person and their organizations.
type Profile struct {
	ID    string  `json:"id"`
	Login string  `json:"login"`
	Name  string  `json:"name,omitempty"`
	Email string  `json:"email,omitempty"`
	Orgs  []MyOrg `json:"orgs"`
}

// Effective is what the person may do in one app inside one organization.
type Effective struct {
	App   string   `json:"app"`
	Org   string   `json:"org"`
	Roles []string `json:"roles"`
	// Permissions are the app's permission keys, e.g. "contacts:read".
	Permissions []string `json:"permissions"`
	// OrgPermissions are qAuth's organization-management permission keys.
	OrgPermissions []string `json:"orgPermissions"`
}

// Has reports whether the person holds the app permission key.
func (e *Effective) Has(permission string) bool {
	return e != nil && contains(e.Permissions, permission)
}

// HasOrgPermission reports whether the person holds the organization
// permission key.
func (e *Effective) HasOrgPermission(permission string) bool {
	return e != nil && contains(e.OrgPermissions, permission)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Org is an organization.
type Org struct {
	ID       string `json:"id"`
	TenantID string `json:"tenantId"`
	Name     string `json:"name"`
	// MFARequired: a second sign-in step for this org's people in every app.
	MFARequired bool `json:"mfaRequired"`
	// MembersMayJoinOthers: its managed people may also join other organizations.
	MembersMayJoinOthers bool      `json:"membersMayJoinOthers"`
	ExternalID           string    `json:"externalId,omitempty"`
	ParentOrgID          string    `json:"parentOrgId,omitempty"`
	LevelID              string    `json:"levelId,omitempty"`
	LevelName            string    `json:"levelName,omitempty"`
	CreatedAt            time.Time `json:"createdAt"`
}

// OrgSettings are an organization's settings (admins).
type OrgSettings struct {
	MembersMayJoinOthers bool `json:"membersMayJoinOthers"`
}

// OrgSecurity is an organization's security rule (admins).
type OrgSecurity struct {
	MFARequired bool `json:"mfaRequired"`
}

// MemberRole is one role a person holds in an organization, from any space.
type MemberRole struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Space is "organization" or an API app's id.
	Space     string `json:"space"`
	SpaceName string `json:"spaceName"`
}

// GivableRole is a role of the organization and whether the caller may give
// it (decided by qAuth).
type GivableRole struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	Space          string   `json:"space"`
	SpaceName      string   `json:"spaceName"`
	Starter        bool     `json:"starter,omitempty"`
	Own            bool     `json:"own,omitempty"`
	OrgPermissions []string `json:"orgPermissions"`
	Permissions    []string `json:"permissions"`
	CanGive        bool     `json:"canGive"`
	// Missing says why it can't be given: what the caller lacks.
	Missing []string `json:"missing,omitempty"`
}

// Member is a person of an organization.
type Member struct {
	ID    string `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	// Role is the one-word summary; Roles lists every role held.
	Role           Role         `json:"role"`
	Roles          []MemberRole `json:"roles,omitempty"`
	OrgPermissions []string     `json:"orgPermissions,omitempty"`
	// Managed: an account at a domain the org verified.
	Managed   bool   `json:"managed"`
	ManagedBy string `json:"managedBy,omitempty"`
}

// NewMember adds a person to an organization.
type NewMember struct {
	Email      string `json:"email"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	// Role is the one-word role (default member); prefer RoleIDs.
	Role Role `json:"role,omitempty"`
	// RoleIDs are roles to give at once (ids from GivableRoles).
	RoleIDs []string `json:"roleIds,omitempty"`
	// Invite emails the person through your tenant's own email channel.
	Invite bool `json:"invite,omitempty"`
}

// AddedMember is the answer to adding a member.
type AddedMember struct {
	User struct {
		ID    string `json:"id"`
		Login string `json:"login"`
		Email string `json:"email,omitempty"`
	} `json:"user"`
	// InitialPassword is set only when a NEW account was created without an
	// invitation: show it once.
	InitialPassword string `json:"initialPassword,omitempty"`
	// Existing: the email already had an account in the directory.
	Existing bool `json:"existing"`
	// Invited: an invitation email went out.
	Invited bool `json:"invited,omitempty"`
}

// Invitation is an invitation to an organization.
type Invitation struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"orgId"`
	Email         string     `json:"email"`
	Role          Role       `json:"role"`
	RoleIDs       []string   `json:"roleIds,omitempty"`
	AppID         string     `json:"appId,omitempty"`
	ReturnURL     string     `json:"returnUrl,omitempty"`
	Status        string     `json:"status"` // pending | accepted | revoked | locked
	Expired       bool       `json:"expired"`
	InvitedBy     string     `json:"invitedBy"`
	InvitedByName string     `json:"invitedByName,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	AcceptedBy    string     `json:"acceptedBy,omitempty"`
	AcceptedAt    *time.Time `json:"acceptedAt,omitempty"`
}

// NewInvitation invites a person.
type NewInvitation struct {
	Email   string   `json:"email"`
	Role    Role     `json:"role,omitempty"`
	RoleIDs []string `json:"roleIds,omitempty"`
	// AppID is the app they are invited to (shown on qAuth's page).
	AppID string `json:"appId,omitempty"`
	// ReturnURL is where "Continue" leads after accepting.
	ReturnURL string `json:"returnUrl,omitempty"`
	// Send: nil or true, qAuth emails the link; false, you deliver
	// SentInvitation.AcceptURL yourself.
	Send *bool `json:"send,omitempty"`
}

// SentInvitation is a created or resent invitation.
type SentInvitation struct {
	Invitation Invitation `json:"invitation"`
	Sent       bool       `json:"sent"`
	// AcceptURL only with Send=false. Shown once; whoever has it can accept.
	AcceptURL string `json:"acceptUrl,omitempty"`
}

// OrgDomain is an email domain of an organization.
type OrgDomain struct {
	ID     string `json:"id"`
	OrgID  string `json:"orgId"`
	Domain string `json:"domain"`
	// Token is the value of the TXT record at _qauth-verify.<domain>.
	Token      string     `json:"token"`
	VerifiedAt *time.Time `json:"verifiedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// AddedDomain is what to publish to prove the org owns the domain.
type AddedDomain struct {
	Domain OrgDomain `json:"domain"`
	// Record is the TXT record's DNS name; its value is Domain.Token.
	Record string `json:"record"`
}

// SSOConnection is an organization's company sign-in (OpenID Connect).
type SSOConnection struct {
	OrgID       string `json:"orgId"`
	Kind        string `json:"kind"`
	DisplayName string `json:"displayName"`
	Issuer      string `json:"issuer"`
	ClientID    string `json:"clientId"`
	Mode        string `json:"mode"` // optional | required
	// SecretSet: the client secret is stored and never returned.
	SecretSet   bool      `json:"secretSet"`
	CallbackURL string    `json:"callbackUrl"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// SSOState says whether company sign-in is connected.
type SSOState struct {
	Connected bool `json:"connected"`
	// CallbackURL is the redirect address to register at the provider.
	CallbackURL string         `json:"callbackUrl"`
	Connection  *SSOConnection `json:"connection,omitempty"`
}

// SSOSpec connects company sign-in.
type SSOSpec struct {
	DisplayName string `json:"displayName"`
	Issuer      string `json:"issuer"`
	ClientID    string `json:"clientId"`
	// ClientSecret is required the first time; empty keeps the stored one.
	ClientSecret string `json:"clientSecret,omitempty"`
	// Mode is optional (default: a button) or required.
	Mode string `json:"mode,omitempty"`
}

// APIKey is an API key or a personal access token (never the secret).
type APIKey struct {
	ID    string `json:"id"`
	OrgID string `json:"orgId"`
	// Kind is m2m (a machine's key) or pat (a person's token).
	Kind        string     `json:"kind,omitempty"`
	UserID      string     `json:"userId,omitempty"`
	Permissions []string   `json:"permissions,omitempty"`
	Name        string     `json:"name"`
	Prefix      string     `json:"prefix"`
	Scopes      []string   `json:"scopes"`
	Apps        []string   `json:"apps"`
	CreatedAt   time.Time  `json:"createdAt"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	RevokedAt   *time.Time `json:"revokedAt,omitempty"`
}

// NewAPIKey creates an organization API key.
type NewAPIKey struct {
	Name string `json:"name"`
	// Permissions are API permission ids (never more than you hold).
	Permissions []string `json:"permissions,omitempty"`
	// Scopes are qAuth's organization-API scopes (qauth:org:*).
	Scopes []string `json:"scopes,omitempty"`
	// Apps are app ids the key is for.
	Apps      []string   `json:"apps,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// MintedAPIKey is a new key and its secret, shown ONCE.
type MintedAPIKey struct {
	Key    APIKey `json:"key"`
	Secret string `json:"secret"`
}

// TokenChoice is one API's permissions a person may put in a personal token.
type TokenChoice struct {
	APIID       string       `json:"apiId"`
	APIName     string       `json:"apiName"`
	Permissions []Permission `json:"permissions"`
}

// NewPersonalToken creates a personal access token.
type NewPersonalToken struct {
	OrgID string `json:"orgId"`
	Name  string `json:"name"`
	// Permissions are permission ids from Tokens.Choices.
	Permissions []string   `json:"permissions"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
}

// App is an app an organization can use.
type App struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Permission is one permission of an app.
type Permission struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Name  string `json:"name"`
	Group string `json:"group,omitempty"`
}

// AppRole is a role of one app: built in, or the organization's own.
type AppRole struct {
	ID    string `json:"id"`
	AppID string `json:"appId"`
	// OrgID is empty for the app's built-in roles.
	OrgID          string    `json:"orgId,omitempty"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Permissions    []string  `json:"permissions"`
	OrgPermissions []string  `json:"orgPermissions,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

// RoleSpec creates or changes an organization's own role.
type RoleSpec struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Permissions are permission ids of the app.
	Permissions    []string `json:"permissions"`
	OrgPermissions []string `json:"orgPermissions,omitempty"`
}

// PersonRoles is who holds which roles of one app.
type PersonRoles struct {
	UserID  string   `json:"userId"`
	Login   string   `json:"login"`
	Name    string   `json:"name,omitempty"`
	RoleIDs []string `json:"roleIds"`
}

// Assignment sets a person's roles of one app.
type Assignment struct {
	AppID   string   `json:"appId"`
	UserID  string   `json:"userId"`
	RoleIDs []string `json:"roleIds"`
}

// AuditEntry is one event of an organization's audit log.
type AuditEntry struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"`
	Actor     string    `json:"actor,omitempty"`
	ActorName string    `json:"actorName,omitempty"`
	Target    string    `json:"target,omitempty"`
	At        time.Time `json:"at"`
}

// AuditQuery filters the audit log. Zero values are left out.
type AuditQuery struct {
	Limit int
	// Before is an event id: older events only.
	Before int64
	// Type: only events whose type starts with this.
	Type string
}

// NewSubOrg creates a child organization.
type NewSubOrg struct {
	Name              string `json:"name"`
	AdminEmail        string `json:"adminEmail"`
	LevelID           string `json:"levelId,omitempty"`
	IsolatedDirectory bool   `json:"isolatedDirectory,omitempty"`
}

// CreatedSubOrg is a new child organization.
type CreatedSubOrg struct {
	Org Org `json:"org"`
	// InitialAdminPassword is set only when the admin's account was new.
	InitialAdminPassword string `json:"initialAdminPassword,omitempty"`
	AdminExisting        bool   `json:"adminExisting"`
}

// Branding is an organization's white-label sign-in look.
type Branding struct {
	AppID       string    `json:"appId,omitempty"`
	OrgID       string    `json:"orgId,omitempty"`
	DisplayName string    `json:"displayName,omitempty"`
	Accent      string    `json:"accent"`
	Background  string    `json:"background"`
	Mode        string    `json:"mode"`     // auto | light | dark
	Language    string    `json:"language"` // auto | en | ar
	HasLogo     bool      `json:"hasLogo"`
	LogoURL     string    `json:"logoUrl,omitempty"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// BrandingSpec sets an organization's sign-in look. Logo is base64 (PNG,
// JPEG or WebP); empty colors mean the parent's or qAuth's.
type BrandingSpec struct {
	DisplayName string `json:"displayName,omitempty"`
	Logo        string `json:"logo,omitempty"`
	RemoveLogo  bool   `json:"removeLogo,omitempty"`
	Accent      string `json:"accent,omitempty"`
	Background  string `json:"background,omitempty"`
	Mode        string `json:"mode,omitempty"`
	Language    string `json:"language,omitempty"`
}

// MySecurity is the person's account page.
type MySecurity struct {
	Email          string `json:"email"`
	HasPassword    bool   `json:"hasPassword"`
	CompanyManaged bool   `json:"companyManaged"`
	Authenticator  bool   `json:"authenticator"`
	// Phone is masked, when a verified phone is set.
	Phone string `json:"phone,omitempty"`
	// RecoveryCodes is how many unused recovery codes are left.
	RecoveryCodes int `json:"recoveryCodes"`
	Passkeys      []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"passkeys"`
	Offered struct {
		Authenticator bool `json:"authenticator"`
		Phone         bool `json:"phone"`
	} `json:"offered"`
}

// Proof is a fresh proof that it is the person: their password, or an
// authenticator code. Set one.
type Proof struct {
	Password string `json:"password,omitempty"`
	Code     string `json:"code,omitempty"`
}

// SessionInfo is one of the person's sign-in sessions.
type SessionInfo struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	LastUsed  time.Time `json:"lastUsed"`
	Device    string    `json:"device,omitempty"`
	IP        string    `json:"ip,omitempty"`
}

// SessionState is a session's sign-out rules and time left.
type SessionState struct {
	SessionID string `json:"sessionId"`
	// IdleMinutes: 0 = no idle limit. MaxMinutes: 0 = no maximum length.
	IdleMinutes int `json:"idleMinutes"`
	MaxMinutes  int `json:"maxMinutes"`
	// IdleSecondsLeft and MaxSecondsLeft: -1 = never.
	IdleSecondsLeft int `json:"idleSecondsLeft"`
	MaxSecondsLeft  int `json:"maxSecondsLeft"`
	// Ended is set when the session is over: signed_out | idle | max_length | client_removed.
	Ended string `json:"ended,omitempty"`
}

// StepUp is a completed step-up: when, and with which second step.
type StepUp struct {
	At     time.Time `json:"at"`
	Method string    `json:"method"`
}

// VerifyOptions picks the channel and language of a verification code.
type VerifyOptions struct {
	// Channel is sms, voice, email or authenticator (default: the template's first).
	Channel string `json:"channel,omitempty"`
	Locale  string `json:"locale,omitempty"`
}

// StartedVerification says where the code went (masked).
type StartedVerification struct {
	RequestID string    `json:"requestId"`
	Channel   string    `json:"channel"`
	SentTo    string    `json:"sentTo"`
	ExpiresAt time.Time `json:"expiresAt"`
	Channels  []string  `json:"channels"`
}

// VerificationCheck is verified, invalid (TriesLeft) or spent.
type VerificationCheck struct {
	Status    string `json:"status"`
	TriesLeft int    `json:"triesLeft"`
}

// ConsumedVerification is what your backend learns, once.
type ConsumedVerification struct {
	RequestID  string            `json:"requestId"`
	Template   string            `json:"template"`
	Variables  map[string]string `json:"variables"`
	Channel    string            `json:"channel"`
	VerifiedAt time.Time         `json:"verifiedAt"`
}

// KeyCheck is the answer to ValidateKey.
type KeyCheck struct {
	Valid bool `json:"valid"`
	// Key is set when Valid: whose key it is and what it may do.
	Key *KeyInfo `json:"key,omitempty"`
}

// KeyInfo describes a valid API key.
type KeyInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	TenantID string `json:"tenantId"`
	OrgID    string `json:"orgId"`
	// Kind is m2m (a machine's key) or pat (a person's token).
	Kind  string    `json:"kind,omitempty"`
	Owner *KeyOwner `json:"owner,omitempty"`
	// Scopes are qAuth's organization-API scopes and older keys' scopes.
	Scopes []string `json:"scopes"`
	// Apps are the apps it works for right now.
	Apps []string `json:"apps"`
	// Permissions: API id -> permission keys, worked out live.
	Permissions map[string][]string `json:"permissions,omitempty"`
	ExpiresAt   *time.Time          `json:"expiresAt,omitempty"`
}

// KeyOwner is whose key it is.
type KeyOwner struct {
	// Type is organization or tenant.
	Type string `json:"type"`
	ID   string `json:"id"`
}

// KeyMay reports whether a checked key may use one permission of one API.
func KeyMay(check KeyCheck, apiID, permission string) bool {
	return check.Valid && check.Key != nil && contains(check.Key.Permissions[apiID], permission)
}

// clone copies the check deeply (answers are shared through the cache).
func (k KeyCheck) clone() KeyCheck {
	if k.Key == nil {
		return k
	}
	ki := *k.Key
	ki.Scopes, ki.Apps = append([]string(nil), ki.Scopes...), append([]string(nil), ki.Apps...)
	if ki.Owner != nil {
		o := *ki.Owner
		ki.Owner = &o
	}
	if ki.ExpiresAt != nil {
		t := *ki.ExpiresAt
		ki.ExpiresAt = &t
	}
	if ki.Permissions != nil {
		m := make(map[string][]string, len(ki.Permissions))
		for a, p := range ki.Permissions {
			m[a] = append([]string(nil), p...)
		}
		ki.Permissions = m
	}
	k.Key = &ki
	return k
}
