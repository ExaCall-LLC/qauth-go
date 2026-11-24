package qauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// These tests run in order against one shared test server (see
// testserver_test.go), like the JS SDK's. Caches are off so every call
// reaches qAuth.

func live(t *testing.T) (*Client, seedInfo) {
	t.Helper()
	s := liveSeed(t)
	c, err := New(s.BaseURL, WithPermissionsCache(0), WithKeyCache(0))
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}

func must[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func wantStatus(t *testing.T, err error, status int) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Status != status {
		t.Fatalf("want HTTP %d, got %v", status, err)
	}
	return e
}

func TestLiveProfileAndOrgs(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	me := c.As("shop-admin-token")
	p := must(me.Profile(ctx))(t)
	if p.Email != "admin@shop.test" || len(p.Orgs) != 1 || p.Orgs[0].ID != s.Shop || p.Orgs[0].Role != RoleAdmin {
		t.Fatalf("%+v", p)
	}
	orgs := must(me.Orgs(ctx))(t)
	if len(orgs.Items) != 1 || orgs.Pagination.Total != 1 || orgs.Pagination.TotalPages != 1 {
		t.Fatalf("%+v", orgs)
	}
	if o2 := must(c.Orgs(ctx, Token("shop-admin-token")))(t); len(o2) != 1 || o2[0].ID != s.Shop {
		t.Fatalf("%+v", o2)
	}
	if len(orgs.Items[0].Levels) != 0 || orgs.Items[0].ParentOrgID != "" {
		t.Fatalf("Shop has no levels and no parent: %+v", orgs.Items[0])
	}
	// levels per product: Cafe is a Customer of the API
	cafe := must(c.Orgs(ctx, Token("cafe-admin-token")))(t)
	if len(cafe) != 1 || len(cafe[0].Levels[s.API]) != 1 || cafe[0].Levels[s.API][0].Name != "Customer" || cafe[0].Levels[s.API][0].ID != s.CustomerLevel || cafe[0].IsInternal {
		t.Fatalf("Cafe's levels: %+v", cafe)
	}
	lv := must(c.As("cafe-admin-token").Org(s.Cafe).Levels(ctx))(t)
	if lv.OrgID != s.Cafe || len(lv.Levels[s.API]) != 1 {
		t.Fatalf("org levels: %+v", lv)
	}
}

func TestLiveBadToken(t *testing.T) {
	c, _ := live(t)
	_, err := c.As("nope").Profile(context.Background())
	e := wantStatus(t, err, 401)
	if e.Code != CodeUnauthorized || !errors.Is(err, ErrUnauthorized) || !strings.HasPrefix(e.RequestID, "req_") {
		t.Fatalf("%+v", e)
	}
}

func TestLiveAdminManagesPeople(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	org := c.As("shop-admin-token").Org(s.Shop)
	if o := must(org.Get(ctx))(t); o.Name != "Shop" || o.CreatedAt.IsZero() {
		t.Fatalf("%+v", o)
	}
	added := must(org.Members.Add(ctx, NewMember{Email: "sara@shop.test", Role: RoleManager}))(t)
	if added.Existing || added.User.ID == "" {
		t.Fatalf("%+v", added)
	}
	find := func() Member {
		for _, m := range must(org.Members.List(ctx))(t).Items {
			if m.Login == "sara@shop.test" {
				return m
			}
		}
		t.Fatal("sara not listed")
		return Member{}
	}
	sara := find()
	if sara.Role != RoleManager {
		t.Fatalf("%+v", sara)
	}
	givable := must(org.GivableRoles(ctx))(t)
	var pick []string
	for _, r := range givable {
		if r.Space == "" {
			t.Fatalf("role without a space: %+v", r)
		}
		if r.CanGive && len(pick) < 2 {
			pick = append(pick, r.ID)
		}
	}
	if len(pick) == 0 {
		t.Fatal("nothing givable")
	}
	if err := org.Members.SetRoles(ctx, sara.ID, pick); err != nil {
		t.Fatal(err)
	}
	var held []string
	for _, r := range find().Roles {
		held = append(held, r.ID)
	}
	slices.Sort(held)
	slices.Sort(pick)
	if !slices.Equal(held, pick) {
		t.Fatalf("held %v, want %v", held, pick)
	}
	if err := org.Members.SetRole(ctx, sara.ID, RoleMember); err != nil {
		t.Fatal(err)
	}
	if find().Role != RoleMember {
		t.Fatal("SetRole")
	}
	if err := org.Members.Remove(ctx, sara.ID); err != nil {
		t.Fatal(err)
	}
}

func TestLiveMemberReadsOnly(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	me := c.As("shop-member-token")
	if o := must(me.Org(s.Shop).Get(ctx))(t); o.ID != s.Shop {
		t.Fatal(o)
	}
	_, err := me.Org(s.Shop).Members.List(ctx)
	if e := wantStatus(t, err, 403); e.Code != CodeForbidden || !errors.Is(err, ErrForbidden) {
		t.Fatalf("%+v", e)
	}
	_, err = me.Org(s.Cafe).Get(ctx)
	wantStatus(t, err, 404)
	_, err = c.As("cafe-admin-token").Org(s.Shop).Members.List(ctx)
	wantStatus(t, err, 404)
}

func TestLiveSettingsSecurityApps(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	org := c.As("shop-admin-token").Org(s.Shop)
	if o := must(org.UpdateSettings(ctx, OrgSettings{MembersMayJoinOthers: true}))(t); !o.MembersMayJoinOthers {
		t.Fatal("settings")
	}
	if o := must(org.SetSecurity(ctx, OrgSecurity{MFARequired: true}))(t); !o.MFARequired {
		t.Fatal("security")
	}
	apps := must(org.Apps(ctx))(t)
	if len(apps.Items) != 1 || apps.Items[0].ID != s.API {
		t.Fatalf("%+v", apps)
	}
}

func TestLiveDomains(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	org := c.As("shop-admin-token").Org(s.Shop)
	d := must(org.Domains.Add(ctx, "shop.test"))(t)
	if d.Domain.Token == "" || d.Record != "_qauth-verify.shop.test" {
		t.Fatalf("%+v", d)
	}
	if n := len(must(org.Domains.List(ctx))(t).Items); n != 1 {
		t.Fatal(n)
	}
	_, err := org.Domains.Verify(ctx, d.Domain.ID)
	wantStatus(t, err, 422)
	if err := org.Domains.Remove(ctx, d.Domain.ID); err != nil {
		t.Fatal(err)
	}
}

func TestLiveAPIKeys(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	org := c.As("shop-admin-token").Org(s.Shop)
	minted := must(org.APIKeys.Create(ctx, NewAPIKey{Name: "Billing sync", Apps: []string{s.App}}))(t)
	if len(minted.Secret) <= 20 || minted.Key.Name != "Billing sync" {
		t.Fatalf("%+v", minted.Key)
	}
	b, _ := json.Marshal(must(org.APIKeys.List(ctx))(t))
	if strings.Contains(string(b), minted.Secret) {
		t.Fatal("the list shows the secret")
	}
	kc := must(c.ValidateKey(ctx, minted.Secret, ValidateKeyOptions{App: s.App}))(t)
	if !kc.Valid || kc.Key.OrgID != s.Shop {
		t.Fatalf("%+v", kc)
	}
	if kc := must(c.ValidateKey(ctx, minted.Secret, ValidateKeyOptions{App: "another-app"}))(t); kc.Valid {
		t.Fatal("valid for another app")
	}
	if err := org.APIKeys.Revoke(ctx, minted.Key.ID); err != nil {
		t.Fatal(err)
	}
	if kc := must(c.ValidateKey(ctx, minted.Secret, ValidateKeyOptions{}))(t); kc.Valid {
		t.Fatal("revoked key still valid")
	}
}

func TestLiveAPIKeyPermissions(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	org := c.As("shop-admin-token").Org(s.Shop)
	in90 := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	minted := must(org.APIKeys.Create(ctx, NewAPIKey{Name: "Contacts sync", Permissions: []string{s.Permission}, ExpiresAt: &in90}))(t)
	if !slices.Equal(minted.Key.Permissions, []string{s.Permission}) {
		t.Fatalf("%+v", minted.Key)
	}
	kc := must(c.ValidateKey(ctx, minted.Secret, ValidateKeyOptions{}))(t)
	if !kc.Valid || kc.Key.Owner == nil || *kc.Key.Owner != (KeyOwner{Type: "organization", ID: s.Shop}) ||
		!slices.Equal(kc.Key.Permissions[s.API], []string{"contacts:read"}) || kc.Key.ExpiresAt == nil {
		t.Fatalf("%+v", kc.Key)
	}
	if !KeyMay(kc, s.API, "contacts:read") || KeyMay(kc, s.API, "contacts:write") {
		t.Fatal("KeyMay")
	}
	if err := org.APIKeys.Revoke(ctx, minted.Key.ID); err != nil {
		t.Fatal(err)
	}
}

func TestLivePersonalTokens(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	me := c.As("shop-member-token")
	choices := must(me.Tokens.Choices(ctx, s.Shop))(t).Items
	if len(choices) != 1 || len(choices[0].Permissions) != 1 || choices[0].Permissions[0].Key != "contacts:read" {
		t.Fatalf("%+v", choices)
	}
	tk := must(me.Tokens.Create(ctx, NewPersonalToken{OrgID: s.Shop, Name: "My script", Permissions: []string{s.Permission}}))(t)
	if tk.Key.Kind != "pat" {
		t.Fatalf("%+v", tk.Key)
	}
	kc := must(c.ValidateKey(ctx, tk.Secret, ValidateKeyOptions{}))(t)
	if kc.Key.Kind != "pat" || !KeyMay(kc, s.API, "contacts:read") {
		t.Fatalf("%+v", kc.Key)
	}
	if n := len(must(me.Tokens.List(ctx))(t).Items); n != 1 {
		t.Fatal(n)
	}
	wantStatus(t, c.As("shop-admin-token").Tokens.Revoke(ctx, tk.Key.ID), 404)
	if err := me.Tokens.Revoke(ctx, tk.Key.ID); err != nil {
		t.Fatal(err)
	}
	if kc := must(c.ValidateKey(ctx, tk.Secret, ValidateKeyOptions{}))(t); kc.Valid {
		t.Fatal("revoked token still valid")
	}
}

func TestLiveRolesAssignmentsPermissionsCan(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	me := c.As("shop-admin-token")
	org := me.Org(s.Shop)
	perms := must(org.Roles.Permissions(ctx, s.App))(t).Items
	if len(perms) != 1 || perms[0].Key != "contacts:read" {
		t.Fatalf("%+v", perms)
	}
	role := must(org.Roles.Create(ctx, s.App, RoleSpec{Name: "Night shift", Permissions: []string{s.Permission}}))(t)
	if role.OrgID != s.Shop {
		t.Fatalf("%+v", role)
	}
	var names []string
	for _, r := range must(org.Roles.List(ctx, s.App))(t).Items {
		names = append(names, r.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"Agent", "Night shift"}) {
		t.Fatal(names)
	}
	_, err := org.Roles.Update(ctx, s.AgentRole, RoleSpec{Name: "x", Permissions: []string{s.Permission}})
	wantStatus(t, err, 404)

	p := must(me.Profile(ctx))(t)
	if err := org.Assignments.Set(ctx, Assignment{AppID: s.App, UserID: p.ID, RoleIDs: []string{role.ID}}); err != nil {
		t.Fatal(err)
	}
	var mine *PersonRoles
	for _, x := range must(org.Assignments.List(ctx, s.App))(t).Items {
		if x.UserID == p.ID {
			mine = &x
		}
	}
	if mine == nil || !slices.Equal(mine.RoleIDs, []string{role.ID}) {
		t.Fatalf("%+v", mine)
	}
	eff := must(me.Permissions(ctx, s.App, s.Shop))(t)
	if !slices.Equal(eff.Permissions, []string{"contacts:read"}) || !eff.Has("contacts:read") {
		t.Fatalf("%+v", eff)
	}
	if yes := must(me.Can(ctx, s.App, s.Shop, "contacts:read"))(t); !yes {
		t.Fatal("can")
	}
	if yes := must(c.Can(ctx, Token("shop-admin-token"), s.App, s.Shop, "contacts:write"))(t); yes {
		t.Fatal("can write")
	}
	// not a member of that org: false, no error; a bad token: an error
	if yes, err := c.Can(ctx, Token("cafe-admin-token"), s.App, s.Shop, "contacts:read"); yes || err != nil {
		t.Fatalf("outsider: %v %v", yes, err)
	}
	_, err = c.Can(ctx, Token("nope"), s.App, s.Shop, "contacts:read")
	wantStatus(t, err, 401)

	if _, err := org.Roles.Update(ctx, role.ID, RoleSpec{Name: "Night shift 2", Permissions: []string{s.Permission}}); err != nil {
		t.Fatal(err)
	}
	if err := org.Roles.Remove(ctx, role.ID); err != nil {
		t.Fatal(err)
	}
}

func TestLiveAudit(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	org := c.As("shop-admin-token").Org(s.Shop)
	must(org.Members.Add(ctx, NewMember{Email: "audit-me@shop.test"}))(t)
	page := must(org.Audit(ctx, AuditQuery{Limit: 5}))(t)
	if !slices.ContainsFunc(page.Items, func(e AuditEntry) bool { return e.Type == "orgs.members.created" }) {
		t.Fatalf("%+v", page.Items)
	}
	_, err := c.As("shop-member-token").Org(s.Shop).Audit(ctx, AuditQuery{})
	wantStatus(t, err, 403)
}

func TestLiveInvitations(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	org := c.As("shop-admin-token").Org(s.Shop)
	no := false
	sent := must(org.Invitations.Create(ctx, NewInvitation{Email: "lina@shop.test", Role: RoleManager, Send: &no}))(t)
	if sent.Sent || !strings.Contains(sent.AcceptURL, "/invite?t=") || sent.Invitation.Status != "pending" {
		t.Fatalf("%+v", sent)
	}
	ls := must(org.Invitations.List(ctx))(t)
	if !slices.ContainsFunc(ls.Items, func(i Invitation) bool { return i.Email == "lina@shop.test" && i.Role == RoleManager }) {
		t.Fatalf("%+v", ls.Items)
	}
	u, _ := url.Parse(sent.AcceptURL)
	b, _ := json.Marshal(ls)
	if strings.Contains(string(b), u.Query().Get("t")) {
		t.Fatal("the list shows the link")
	}
	again := must(org.Invitations.Resend(ctx, sent.Invitation.ID, false))(t)
	if again.AcceptURL == "" || again.AcceptURL == sent.AcceptURL {
		t.Fatal("resend")
	}
	if err := org.Invitations.Revoke(ctx, sent.Invitation.ID); err != nil {
		t.Fatal(err)
	}
	_, err := c.As("shop-member-token").Org(s.Shop).Invitations.Create(ctx, NewInvitation{Email: "y@shop.test", Send: &no})
	wantStatus(t, err, 403)
}

func TestLiveSSO(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	org := c.As("shop-admin-token").Org(s.Shop)
	st := must(org.SSO.Get(ctx))(t)
	if st.Connected || !strings.HasSuffix(st.CallbackURL, "/idps/callback") {
		t.Fatalf("%+v", st)
	}
	_, err := org.SSO.Set(ctx, SSOSpec{DisplayName: "Shop account", Issuer: "https://login.example.test", ClientID: "c", ClientSecret: "s"})
	if e := wantStatus(t, err, 422); !strings.Contains(strings.ToLower(e.Message), "verify at least one email domain") {
		t.Fatal(e.Message)
	}
	wantStatus(t, org.SSO.Remove(ctx), 404)
	_, err = c.As("shop-member-token").Org(s.Shop).SSO.Get(ctx)
	wantStatus(t, err, 403)
}

func TestLiveSubOrgsBrandingResetPassword(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	org := c.As("shop-admin-token").Org(s.Shop)
	if subs := must(org.SubOrgs.List(ctx))(t); len(subs.Items) != 0 {
		t.Fatalf("%+v", subs)
	}
	_, err := c.As("shop-member-token").Org(s.Shop).SubOrgs.Create(ctx, NewSubOrg{Name: "Branch", AdminEmail: "b@shop.test"})
	wantStatus(t, err, 403)

	b := must(org.Branding.Get(ctx, ""))(t)
	if b.Mode == "" {
		t.Fatalf("%+v", b)
	}
	set := must(org.Branding.Set(ctx, "", BrandingSpec{DisplayName: "Shop", Accent: "#112233", Mode: "dark", Language: "ar"}))(t)
	if set.Accent != "#112233" || set.Mode != "dark" || set.OrgID != s.Shop {
		t.Fatalf("%+v", set)
	}
	if err := org.Branding.Remove(ctx, ""); err != nil {
		t.Fatal(err)
	}
	_, err = org.Branding.Set(ctx, "", BrandingSpec{Accent: "red"})
	wantStatus(t, err, 422)

	added := must(org.Members.Add(ctx, NewMember{Email: "reset-me@shop.test"}))(t)
	// a personal (not managed) account: only the person changes its password
	err = org.Members.ResetPassword(ctx, added.User.ID, "Another-good-pass-9!", true)
	if e := wantStatus(t, err, 403); !strings.Contains(e.Message, "personal account") {
		t.Fatal(e.Message)
	}
	wantStatus(t, c.As("shop-member-token").Org(s.Shop).Members.ResetPassword(ctx, added.User.ID, "Another-good-pass-9!", false), 403)
}

func TestLiveMyAccount(t *testing.T) {
	c, _ := live(t)
	ctx := context.Background()
	me := c.As("shop-admin-token").Account
	sec := must(me.Security(ctx))(t)
	if !sec.HasPassword || sec.Authenticator {
		t.Fatalf("%+v", sec)
	}
	wantStatus(t, me.ChangePassword(ctx, "wrong", "Brand-new-pass-1!"), 422)
	if err := me.ChangePassword(ctx, "Pass-shop-admin-1!", "Brand-new-pass-1!"); err != nil {
		t.Fatal(err)
	}
	uri, _, err := me.Authenticator.Start(ctx)
	if err != nil || !strings.HasPrefix(uri, "otpauth:") {
		t.Fatal(uri, err)
	}
	if err := me.Authenticator.Verify(ctx, "123456"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, me.Authenticator.Remove(ctx, Proof{Password: "nope"}), 422)
	if codes := must(me.RecoveryCodes(ctx, nil))(t); len(codes) != 10 {
		t.Fatal(codes)
	}
	_, err = me.RecoveryCodes(ctx, nil)
	wantStatus(t, err, 422) // proof needed now
	if codes := must(me.RecoveryCodes(ctx, &Proof{Code: "123456"}))(t); len(codes) != 10 {
		t.Fatal(codes)
	}
	if err := me.Authenticator.Remove(ctx, Proof{Code: "123456"}); err != nil {
		t.Fatal(err)
	}
	ss := must(me.Sessions.List(ctx))(t)
	if len(ss.Items) != 2 {
		t.Fatalf("%+v", ss)
	}
	wantStatus(t, me.Sessions.End(ctx, "sess-cafe-admin-1"), 404)
	if err := me.Sessions.End(ctx, ss.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	if n := must(me.Sessions.EndAll(ctx))(t); n != 1 {
		t.Fatal(n)
	}
}

func TestLiveSessionStateSharedSession(t *testing.T) {
	c, _ := live(t)
	ctx := context.Background()
	me := c.As("cafe-admin-token").Account
	if st := must(me.Sessions.State(ctx, "sess-shared", "cid-second"))(t); st.IdleMinutes != 5 {
		t.Fatalf("%+v", st)
	}
	if st := must(me.Sessions.State(ctx, "sess-shared", "cid-first"))(t); st.IdleMinutes != 30 {
		t.Fatalf("%+v", st)
	}
	_, err := me.Sessions.State(ctx, "sess-shared", "")
	wantStatus(t, err, 400) // shared: the app must be named
	if st := must(me.Sessions.Activity(ctx, "sess-shared", "cid-second"))(t); st.IdleMinutes != 5 {
		t.Fatalf("%+v", st)
	}
}

func TestLiveOrgAPIKey(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	org := c.WithKey(s.OrgKey).Org(s.Shop)
	if n := len(must(org.Members.List(ctx))(t).Items); n < 1 {
		t.Fatal(n)
	}
	if a := must(org.Members.Add(ctx, NewMember{Email: "via-key@shop.test"}))(t); a.Existing {
		t.Fatal("existing")
	}
	_, err := org.Members.Add(ctx, NewMember{Email: "boss@shop.test", Role: RoleAdmin})
	wantStatus(t, err, 403)
	_, err = org.UpdateSettings(ctx, OrgSettings{MembersMayJoinOthers: true})
	wantStatus(t, err, 403)
	_, err = org.APIKeys.List(ctx)
	wantStatus(t, err, 403)
	_, err = c.WithKey(s.OrgKey).Org(s.Cafe).Members.List(ctx)
	wantStatus(t, err, 404)
}

func TestLiveStepUp(t *testing.T) {
	c, _ := live(t)
	got, err := c.As("shop-admin-token").Account.LastStepUp(context.Background(), "some-client")
	if err != nil || got != nil {
		t.Fatal(got, err)
	}
	if StepUpParams["max_age"] != "0" {
		t.Fatal(StepUpParams)
	}
}

func TestLiveVerifications(t *testing.T) {
	c, _ := live(t)
	ctx := context.Background()
	me := c.As("shop-member-token")
	v := must(me.Verifications.Start(ctx, "Money transfer", map[string]string{"amount": "500"}, VerifyOptions{}))(t)
	if v.Channel != "sms" || v.SentTo == "+966512345678" || !slices.Equal(v.Channels, []string{"sms", "voice"}) {
		t.Fatalf("%+v", v)
	}
	if ch := must(me.Verifications.Check(ctx, v.RequestID, "0000"))(t); *ch != (VerificationCheck{Status: "invalid", TriesLeft: 2}) {
		t.Fatalf("%+v", ch)
	}
	if ch := must(me.Verifications.Check(ctx, v.RequestID, "1234"))(t); ch.Status != "verified" {
		t.Fatalf("%+v", ch)
	}
	_, err := me.Verifications.Consume(ctx, v.RequestID, "Money transfer", map[string]string{"amount": "5000"})
	wantStatus(t, err, 409)
	_, err = c.As("shop-admin-token").Verifications.Consume(ctx, v.RequestID, "Money transfer", map[string]string{"amount": "500"})
	wantStatus(t, err, 404)
	used := must(me.Verifications.Consume(ctx, v.RequestID, "Money transfer", map[string]string{"amount": "500"}))(t)
	if used.Template != "Money transfer" {
		t.Fatalf("%+v", used)
	}
	_, err = me.Verifications.Consume(ctx, v.RequestID, "Money transfer", map[string]string{"amount": "500"})
	wantStatus(t, err, 409)
	r := must(me.Verifications.Start(ctx, "Money transfer", map[string]string{"amount": "1"}, VerifyOptions{}))(t)
	if again := must(me.Verifications.Resend(ctx, r.RequestID, VerifyOptions{Channel: "voice"}))(t); again.Channel != "voice" {
		t.Fatalf("%+v", again)
	}
}

func TestLiveOrgDesign(t *testing.T) {
	c, s := live(t)
	ctx := context.Background()
	org := c.As("shop-admin-token").Org(s.Shop)
	png, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")
	pic := must(org.Design.AddPicture(ctx, png))(t)
	if pic.ContentType != "image/png" || len(pic.Hash) != 64 {
		t.Fatalf("%+v", pic)
	}
	v := must(org.Design.Set(ctx, "", BrandingSpec{Accent: "#112233", Design: &Design{Layout: "split", FormSide: "start",
		Panel: &DesignPanel{Background: PanelBackground{Kind: "image", Image: pic.Hash, Overlay: "#FFFFFF", OverlayOpacity: 50},
			Blocks: []DesignBlock{{ID: "l", Type: "link", URL: "https://shop.test/help", Label: &I18nText{EN: "Help", AR: "مساعدة"}, Style: "outline"}}}}}))(t)
	if !v.Own || v.Look.Design.FormSide != "start" || v.Look.Accent != "#112233" || v.Limits.MaxBlocks == 0 {
		t.Fatalf("%+v", v)
	}
	// the old branding call keeps the design
	if _, err := org.Branding.Set(ctx, "", BrandingSpec{Accent: "#445566"}); err != nil {
		t.Fatal(err)
	}
	if got := must(org.Design.Get(ctx, ""))(t); got.Look.Design.Layout != "split" || got.Look.Accent != "#445566" {
		t.Fatalf("%+v", got.Look)
	}
	_, err := org.Design.Set(ctx, "", BrandingSpec{Design: &Design{Layout: "split", Panel: &DesignPanel{Background: PanelBackground{Kind: "color"},
		Blocks: []DesignBlock{{ID: "x", Type: "text", Text: &I18nText{EN: "<b>hi</b>"}}}}}})
	wantStatus(t, err, 422)
	_, err = c.As("shop-member-token").Org(s.Shop).Design.Set(ctx, "", BrandingSpec{})
	wantStatus(t, err, 403)
	if err := org.Design.Reset(ctx, ""); err != nil {
		t.Fatal(err)
	}
}
