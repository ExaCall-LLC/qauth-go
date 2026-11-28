# qAuth Go SDK

`github.com/ExaCall-LLC/qauth-go` (package `qauth`) is for the **backends** of products that use
qAuth for sign-in and authorization. It does four jobs:

- **Verify access tokens offline**: the signature against the issuer's published keys, the issuer, the
  client, the audience and the times. No call to qAuth per request. `net/http` middleware included.
- **Permissions**: what a person may do in one of your apps inside one organization (`Can`), with a
  short cache.
- **API keys**: check a key a customer's system sent to your API (`ValidateKey`, `KeyMay`).
- **API clients**: qAuth's person API (as the person, with their access token) and organization API
  (as a person, or with an organization's API key).

It is its own Go module: it never imports qAuth's server code. Its only dependency is
[go-jose](https://github.com/go-jose/go-jose) v4. Go 1.24+.

The same calls exist in the TypeScript SDK (`@isdlc.ai/qauth`, `sdk/js`) with the same names (in
camelCase) and the same behaviour.

## Install

The module is public: no account, token or `GOPRIVATE` needed.

```bash
go get github.com/ExaCall-LLC/qauth-go@v0.5.0
```

```go
import qauth "github.com/ExaCall-LLC/qauth-go"
```

Its source is at [github.com/ExaCall-LLC/qauth-go](https://github.com/ExaCall-LLC/qauth-go) (MIT). That
repository is a read-only copy: the SDK is developed inside qAuth's repository (`sdk/go`) and CI
publishes each new version there.

Apps that still import the old private path `github.com/ExaCall-LLC/qauth/sdk/go` (up to 0.2.0) keep
working with their git access; to move, change the import path and `go get` the line above. Nothing
else changed.

## Quick start

```go
// Once at start-up: your tenant's issuer (https://<tenant domain> or
// https://<slug>.<managed zone>) and your app's client id. qAuth's API address
// comes from the issuer's discovery (qauth_api); a Verifier for this issuer and
// client is wired in.
client, err := qauth.FromIssuer(ctx, "https://acme.qapps.dev", "omni-web",
	qauth.WithAPIKey(os.Getenv("QAUTH_ORG_API_KEY"))) // optional: client.Org(id) with an organization's key
if err != nil { log.Fatal(err) }
verifier := client.Verifier()

mux := http.NewServeMux()
mux.Handle("GET /contacts", verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	id, _ := qauth.IdentityFrom(r.Context()) // always set behind Middleware
	ok, err := client.Can(r.Context(), id, appID, r.URL.Query().Get("org"), "contacts:read")
	if err != nil { qauth.WriteError(w, err); return }
	if !ok { http.Error(w, "not allowed", http.StatusForbidden); return }
	// ... id.Subject is the person
})))
```

The issuer is trusted for tokens only; the API address it names must be a known qAuth host (`auth.qapps.dev`; add
yours with `qauth.WithTrustedAPIHosts`). Several clients or issuers, or an audience: build the verifier with `qauth.NewVerifier` and pass
`qauth.WithVerifier(v)`. A qAuth server without `qauth_api` in discovery (older), or local development without
qAuth's proxy: `qauth.New("https://auth.qapps.dev", qauth.WithVerifier(v))` as before.

Decide on permission **keys** (`contacts:read`), never on role names: roles are data each organization
edits.

## Verifying tokens

```go
id, err := verifier.Verify(ctx, accessToken)
// id.Subject, id.ClientID, id.Issuer, id.ExpiresAt, id.Claims, id.Token
// (access tokens carry no session id: for the session calls use the sid of the ID token you got at sign-in)
```

`VerifierConfig`:

| Field | Default | Meaning |
|---|---|---|
| `Issuers` | required | accepted `iss` values, exact match; discovery is fetched only for these. `https://` only (`http://` only for localhost, 127.0.0.1, ::1); the keys address in discovery likewise |
| `ClientIDs` | required | accepted clients: the token's `client_id` (required; no `azp` fallback). This is what restricts which apps' tokens get in |
| `Audiences` | none | when set, the token's `aud` must hold one of them; empty means any audience (only `ClientIDs` restrict) |
| `Leeway` | 60 s | clock difference allowed for `exp`, `nbf`, `iat` (negative: none) |
| `Algorithms` | the issuer's | narrows the issuer's published algorithms; public-key ones only (`none` and `HS*` are always refused) |
| `KeysCooldown` | 30 s | a token with an unknown key id fetches the keys again at most this often per issuer |
| `KeysMaxAge` | 600 s | the keys are fetched again after this long; if the issuer is down then, 503 (a retired key never outlives an outage) |
| `DiscoveryCacheTTL` | 3600 s | each issuer's discovery document is kept this long (then as for the keys) |
| `HTTPClient` | 5 s timeout, no redirects | fetches discovery and keys; your own must not follow redirects (`CheckRedirect` returning `http.ErrUseLastResponse`) and needs a timeout |
| `FetchTimeout` | 5 s | each discovery or keys fetch runs apart from the request that triggered it (a cancelled request never cuts it short) |
| `FailureBackoff` | 5 s | after a failed fetch, that issuer's tokens get 503 at once for this long, without trying again |

The issuer named in discovery must equal the token's issuer. A failed fetch is never kept.

Only **access tokens** are accepted. An ID token (it carries `azp`, `at_hash`, `nonce`, `auth_time`, `sid` or `amr`), or a
token whose `typ` header is not absent, `JWT` or `at+jwt`, is refused with `NOT_ACCESS_TOKEN`. `sub` must be
a non-empty string. Claims are read case-sensitively (`SUB` is not `sub`).

A fetch is shared by every request waiting for it, and no lock is held while it runs; a request whose
context ends stops waiting (503) while the fetch carries on for the next one.

### Middleware

```go
handler = verifier.Middleware(next)         // a token is required
handler = verifier.OptionalMiddleware(next) // no token: through without identity; a bad one: 401
id, ok := qauth.IdentityFrom(r.Context())
```

A missing token is answered `401` with `WWW-Authenticate: Bearer realm="api"`; a refused one `401` with
`Bearer realm="api", error="invalid_token", error_description="<CODE>"`; `503` when the issuer's keys
could not be fetched. The body is `{"success":false,"status":401,"message":"<CODE>","error":{"code":"<CODE>","message":"Please sign in."}}`.
Use `qauth.WriteError(w, err)` to answer any SDK error the same way, and `qauth.ContextWithIdentity` in
your own handler tests.

## Permissions

```go
eff, err := client.Permissions(ctx, id, appID, orgID)   // {App, Org, Roles, Permissions, OrgPermissions}
ok, err := client.Can(ctx, id, appID, orgID, "contacts:read")
orgs, err := client.Orgs(ctx, id)                         // []MyOrg{ID, Name, Role}
client.Forget(ctx, id)                                    // drop what is kept about the person
```

`who` is a verified `*Identity` or a raw `qauth.Token(accessToken)`. With `WithVerifier`, a raw token is
verified offline first (a refused token never reaches qAuth) and answers are kept per person (issuer +
`sub`); without it, per token (a SHA-256 of it, never the token itself).

`Can` answers `false` when qAuth says the person is not in the organization (403/404); a `401` (their
session is over) is an error.

## API keys (machines calling your API)

```go
check, err := client.ValidateKey(ctx, r.Header.Get("X-Api-Key"), qauth.ValidateKeyOptions{App: appID})
if err != nil { qauth.WriteError(w, err); return }   // qAuth unreachable, rate limited...
if !check.Valid { http.Error(w, "bad key", 401); return }
if !qauth.KeyMay(check, apiID, "contacts:read") { http.Error(w, "not allowed", 403); return }
// check.Key: ID, Name, Kind (m2m | pat), Owner{Type, ID}, OrgID, TenantID, Apps, Permissions, ExpiresAt
```

A revoked, expired or unknown key is `Valid: false` with no error.

## The person's API (as the signed-in person)

```go
me := client.As(accessToken)
p, err := me.Profile(ctx)                        // ID, Login, Name, Email, Orgs
orgs, err := me.Orgs(ctx)                        // *Page[MyOrg]
eff, err := me.Permissions(ctx, appID, orgID)
ok, err := me.Can(ctx, appID, orgID, "contacts:read")

// personal access tokens (a subset of the person's own permissions, in one org)
choices, err := me.Tokens.Choices(ctx, orgID)
tk, err := me.Tokens.Create(ctx, qauth.NewPersonalToken{OrgID: orgID, Name: "My script", Permissions: []string{permID}})
// tk.Secret is shown ONCE
page, err := me.Tokens.List(ctx)
err = me.Tokens.Revoke(ctx, tk.Key.ID)

// my account
sec, err := me.Account.Security(ctx)
err = me.Account.ChangePassword(ctx, current, next)
// a change to second steps needs the person to confirm it's them: their
// password, plus a code when they have an authenticator app (403
// CONFIRM_NEEDED says what is missing; never a set-up first)
uri, secret, err := me.Account.Authenticator.Start(ctx, &qauth.Proof{Password: pw})   // show uri as a QR code
err = me.Account.Authenticator.Verify(ctx, "123456")
err = me.Account.Authenticator.Remove(ctx, qauth.Proof{Password: pw, Code: "123456"})
sentTo, err := me.Account.Phone.Add(ctx, "+966512345678", &qauth.Proof{Password: pw})
err = me.Account.Phone.Verify(ctx, code)
err = me.Account.Phone.Remove(ctx, qauth.Proof{Password: pw})
codes, err := me.Account.RecoveryCodes(ctx, &qauth.Proof{Password: pw, Code: "123456"}) // always confirmed
err = me.Account.RemovePasskey(ctx, passkeyID, qauth.Proof{Password: pw, Code: "123456"})

// sessions
ss, err := me.Account.Sessions.List(ctx)
err = me.Account.Sessions.End(ctx, sessionID)
n, err := me.Account.Sessions.EndAll(ctx)                   // signs out everywhere
st, err := me.Account.Sessions.State(ctx, sid, clientID)    // idle rules and seconds left
st, err = me.Account.Sessions.Activity(ctx, sid, clientID)  // "still here", at most once a minute
// instant sign-out: a context that ends the moment the session does (run websockets/streams under it)
wctx, stop := me.Account.Sessions.Watch(ctx, sid, qauth.WatchOptions{ClientID: clientID})
defer stop()
<-wctx.Done(); why := qauth.SessionEnded(wctx) // "" = stopped, or qauth.ErrTokenRefused

// step-up: redirect to your authorize URL with qauth.StepUpParams (max_age=0), note startedAt, then
last, err := client.As(newAccessToken).Account.LastStepUp(ctx, clientID) // nil: none
if qauth.IsFreshStepUp(last, startedAt, 0) { /* allow */ }

// action verification: a code to the person's own phone or email
v, err := me.Verifications.Start(ctx, "Money transfer", map[string]string{"amount": "500"}, qauth.VerifyOptions{})
c, err := me.Verifications.Check(ctx, v.RequestID, code)                 // verified | invalid | spent
v, err = me.Verifications.Resend(ctx, v.RequestID, qauth.VerifyOptions{Channel: "voice"})
used, err := me.Verifications.Consume(ctx, v.RequestID, "Money transfer", map[string]string{"amount": "500"})
// 409 unless verified by this person for exactly these values, and never used

// add a passkey on your app's page (your server keeps the token; your page
// runs navigator.credentials.create with begun.Options and posts the answer back)
begun, err := me.Account.Passkeys().Begin(ctx, "https://app.example.com", false)
added, err := me.Account.Passkeys().Finish(ctx, "https://app.example.com", begun.Ceremony, credentialJSON, "")
// a sign-in that isn't fresh enough: *qauth.StepNeededError with the ways
// (passkey, code, sms, email); confirm with Step + VerifyStep, then Begin again
var step *qauth.StepNeededError
if errors.As(err, &step) {
	st, err := me.Account.Passkeys().Step(ctx, "https://app.example.com", step.Ways[0])
	err = me.Account.Passkeys().VerifyStep(ctx, "https://app.example.com", st.Way, st.Step, nil, code)
}

// your server relays: pass the person's browser so the passkey's name, the
// notice email and the step's limits are theirs, not your server's
me = client.AsBrowser(accessToken, qauth.Browser{UserAgent: r.UserAgent(), IP: browserIP})
```

`UserAgent` and `IP` (headers `X-QAuth-Client-UA`, `X-QAuth-Client-IP`) never grant access. Which sign-in a
token belongs to needs nothing from you: qAuth ties each access token to its sign-in when it issues it.

## The organization API

```go
org := client.As(accessToken).Org(orgID)        // a person (members only; others get 404)
org = client.WithKey(orgAPIKey).Org(orgID)       // an org's API key, within its qauth:org:* scopes

o, err := org.Get(ctx)
o, err = org.UpdateSettings(ctx, qauth.OrgSettings{MembersMayJoinOthers: true})   // admins
o, err = org.SetSecurity(ctx, qauth.OrgSecurity{MFARequired: true})              // admins
apps, err := org.Apps(ctx)
roles, err := org.GivableRoles(ctx)               // every role, CanGive and Missing
audit, err := org.Audit(ctx, qauth.AuditQuery{Limit: 50})

// members
page, err := org.Members.List(ctx)
added, err := org.Members.Add(ctx, qauth.NewMember{Email: "sara@shop.com", RoleIDs: []string{roleID}, Invite: true})
err = org.Members.SetRoles(ctx, userID, []string{roleID})      // replaces roles in every space
err = org.Members.SetRole(ctx, userID, qauth.RoleManager)      // the one-word role; prefer SetRoles
err = org.Members.ResetPassword(ctx, userID, newPassword, true) // managed accounts only
err = org.Members.Remove(ctx, userID)

// invitations (no account until the person accepts)
no := false
sent, err := org.Invitations.Create(ctx, qauth.NewInvitation{Email: "lina@shop.com", RoleIDs: ids, Send: &no})
// sent.AcceptURL only with Send=false, shown once
inv, err := org.Invitations.List(ctx)
sent, err = org.Invitations.Resend(ctx, invitationID, true)
err = org.Invitations.Revoke(ctx, invitationID)

// the org's own roles for one app, and who holds them
perms, err := org.Roles.Permissions(ctx, appID)
role, err := org.Roles.Create(ctx, appID, qauth.RoleSpec{Name: "Night shift", Permissions: []string{permID}})
list, err := org.Roles.List(ctx, appID)
role, err = org.Roles.Update(ctx, role.ID, qauth.RoleSpec{Name: "Nights", Permissions: []string{permID}})
err = org.Roles.Remove(ctx, role.ID)
who, err := org.Assignments.List(ctx, appID)
err = org.Assignments.Set(ctx, qauth.Assignment{AppID: appID, UserID: userID, RoleIDs: []string{role.ID}})

// verified email domains
d, err := org.Domains.Add(ctx, "shop.com")       // publish TXT d.Record = d.Domain.Token
dom, err := org.Domains.Verify(ctx, d.Domain.ID) // 422 while the record is missing
ds, err := org.Domains.List(ctx)
err = org.Domains.Remove(ctx, d.Domain.ID)

// API keys (admins; the secret is shown once)
k, err := org.APIKeys.Create(ctx, qauth.NewAPIKey{Name: "Billing sync", Permissions: []string{permID}})
ks, err := org.APIKeys.List(ctx)
err = org.APIKeys.Revoke(ctx, k.Key.ID)

// company sign-in (admins; needs a verified domain)
st, err := org.SSO.Get(ctx)                      // st.CallbackURL: register it at the provider
st, err = org.SSO.Set(ctx, qauth.SSOSpec{DisplayName: "Contoso account", Issuer: iss, ClientID: cid, ClientSecret: sec, Mode: "required"})
err = org.SSO.Remove(ctx)

// child organizations and white-label sign-in look ("" = the org's own; an app id = its override)
subs, err := org.SubOrgs.List(ctx)
child, err := org.SubOrgs.Create(ctx, qauth.NewSubOrg{Name: "Branch", AdminEmail: "boss@shop.com"})
// the first admin may be anyone; child.Invited: a new one was emailed (no password comes back)
b, err := org.Branding.Get(ctx, "")
b, err = org.Branding.Set(ctx, "", qauth.BrandingSpec{Accent: "#5B21B6", Mode: "auto", Language: "ar"})
err = org.Branding.Remove(ctx, "")

// the sign-in page design ("" = the org's own look; an app id = its look for that app)
pic, err := org.Design.AddPicture(ctx, pngBytes) // PNG, JPEG, WebP or GIF; never SVG
v, err := org.Design.Set(ctx, "", qauth.BrandingSpec{Accent: "#1F2937", Design: &qauth.Design{
	Layout: "split", FormSide: "end", Font: "Public Sans", Phone: "banner",
	Texts: &qauth.DesignTexts{EN: qauth.TitleText{Title: "Sign in to Shop"}, AR: qauth.TitleText{Title: "تسجيل الدخول إلى المتجر"}},
	Panel: &qauth.DesignPanel{
		Background: qauth.PanelBackground{Kind: "image", Image: pic.Hash, Overlay: "#FFFFFF", OverlayOpacity: 88},
		Blocks: []qauth.DesignBlock{{ID: "h1", Type: "heading", Text: &qauth.I18nText{EN: "Welcome", AR: "مرحبًا"}, Size: "m", Align: "center"}},
	},
}})
// v.Own, v.InheritedFrom["level"], v.Limits.Fonts / MaxBlocks ...
err = org.Design.Reset(ctx, "")                  // inherit again
```

Lists answer `*Page[T]{Items, Pagination}`. Admins manage the organization; managers manage people
(never the admin role); members read.

## App definition files (the `qauth` command)

An app's authorization model can live in its own repository as `qauth.app.yaml`
([the guide](https://auth.qapps.dev/docs/app-definition)). CI plans and applies it with a setup key:

```sh
go install github.com/ExaCall-LLC/qauth-go/cmd/qauth@v0.7.0   # pin the version in CI
export QAUTH_SETUP_KEY=qsk_...            # Console: the API › Setup keys
qauth plan qauth.app.yaml                 # what would change (nothing is changed)
qauth apply qauth.app.yaml --apply        # make the changes (add --prune to remove what the file dropped)
```

`QAUTH_API_URL` defaults to `https://auth.qapps.dev`. Flags: `--apply`, `--prune`, `--plan-hash`, `--json`, `--source`,
`--path`, `--commit`, `--ref` (read from GitHub Actions, Woodpecker CI or git when not given). Exit codes:
0 done (dry run, applied, nothing to do), 1 refused or failed (the plan says why), 2 a usage mistake
(no key, no file), 3 qAuth refused the key or could not be reached. It prints the same plan as
`npx @isdlc.ai/qauth-cli`: qAuth makes the plan, the tools only show it.

From Go code, the same calls:

<!-- no-compile: a fragment with placeholders -->
```go
sc, err := qauth.NewSetupClient(qauth.DefaultSetupURL, os.Getenv("QAUTH_SETUP_KEY"), nil)
res, err := sc.Plan(ctx, qauth.SetupRequest{Content: string(file), Source: "github.com/acme/shop", Commit: sha})
fmt.Print(res.Text) // res.Result: dry-run | applied | no-changes | refused | failed
```

## Errors

Every refusal is a `*qauth.Error`:

```go
type Error struct {
	Status     int                 // HTTP status; 0 when qAuth could not be reached
	Code       string              // stable: FORBIDDEN, RATE_LIMITED, TOKEN_EXPIRED...
	Message    string              // plain words
	RequestID  string              // qAuth's request id, for support
	Fields     map[string][]string // field messages of a 422
	RetryAfter time.Duration       // from Retry-After (seconds or an HTTP date), on 429/503
	Err        error               // the cause, when there is one
}
```

Match with `errors.Is(err, qauth.ErrForbidden)` (it compares codes) or read it with `errors.As`.
`qauth.StatusOf(err)` gives the status.

| Code | Status | When |
|---|---|---|
| `TOKEN_MISSING`, `TOKEN_MALFORMED`, `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID`, `WRONG_ISSUER`, `WRONG_CLIENT`, `WRONG_AUDIENCE`, `BAD_SIGNATURE`, `NOT_ACCESS_TOKEN` | 401 | a token your API refused |
| `KEYS_UNAVAILABLE` | 503 | the issuer's discovery or keys could not be fetched |
| `UNAUTHORIZED`, `FORBIDDEN`, `RESOURCE_NOT_FOUND`, `VALIDATION_ERROR`, `CONFLICT`, `RATE_LIMITED`... | qAuth's | qAuth's answer |
| `UNAVAILABLE` | 0 | qAuth could not be reached (or did not answer in time) |
| `UNEXPECTED_REDIRECT` | qAuth's 3xx | qAuth answered a redirect: never followed, so a token or key never goes elsewhere (check the base address) |
| `INVALID_ARGUMENT` | 0 | an id was empty, `.` or `..`: nothing was sent |
| `BAD_RESPONSE` | qAuth's | an answer without qAuth's JSON envelope |

## Caching

| What | Default | Option |
|---|---|---|
| `Permissions`, `Can`, `Orgs` | 60 s per person, app and org | `qauth.WithPermissionsCache(d)`; 0 = always ask |
| `ValidateKey` | off: a revoked key stops at once | `qauth.WithKeyCache(30 * time.Second)` recommended for busy APIs |
| issuer discovery / keys | 3600 s / 600 s; unknown key id: refetch at most every 30 s | `VerifierConfig` |

Only successful answers are kept; concurrent asks for the same thing share one request. Keys of the
caches are hashes (or issuer + subject), never tokens or API keys. `client.Forget(ctx, who)` and
`client.ForgetKeys()` drop kept answers. Each cache holds at most 10000 entries (`WithCacheSize`).

Other options: `WithHTTPClient` (your client must not follow redirects and needs a timeout), `WithTimeout`
(default 15 s). The base address must be `https://` (`http://` only for localhost).

## Versioning

Semantic versions. Each version is a tag `vX.Y.Z` of
[github.com/ExaCall-LLC/qauth-go](https://github.com/ExaCall-LLC/qauth-go); `qauth.Version` holds the same
number. CI refuses a change to the package's code without a new `Version` (and a line below). After the
merge to main, CI copies `sdk/go` to the public repository and tags the version (only versions not tagged
yet; nothing to do by hand).

## Tests

In qAuth's repository, `go test ./...` in `sdk/go` builds and starts `tools/sdk-testserver` (qAuth's real
routes over in-memory stores), or uses the binary in `QAUTH_SDK_TESTSERVER`. The public copy does not carry
that server, so there the API-client tests need `QAUTH_SDK_TESTSERVER`. Token tests use a fake issuer with
keys generated in the test.

## Changes

- **0.20.0** (2026-11-28): `client.AsBrowser(token, qauth.Browser{UserAgent, IP})`: pass the person's browser's
  User-Agent and address (`X-QAuth-Client-UA`, `X-QAuth-Client-IP`) for the passkey's name, the notice email, the audit
  and the inline step's limits; never for access. `As` is unchanged (qAuth EXA-640).
- **0.19.0** (2026-11-28): `AppPasskeys.Begin` keeps the ways to confirm with: a 403 `STEP_NEEDED` is a `*StepNeededError` with `Ways` (`StepWayPasskey`, `StepWayCode`, `StepWaySMS`, `StepWayEmail`) and the app's `PasskeyAddFreshness`; it wraps the `*Error` (same `Status`, `Code`, `Message`; `errors.Is(err, ErrStepNeeded)`). `Error.Data` holds what came with any refusal. Before, the ways were dropped, and the doc named a `StepWays` that didn't exist. Nothing removed (qAuth EXA-639).
- **0.18.0** (2026-11-28): add a passkey on your app's own page when your server keeps the tokens: `me.Account.Passkeys()` with `Begin(ctx, origin, popup)`, `Finish(ctx, origin, ceremony, credential, name)`, and the inline check `Step` / `VerifyStep` (403 `STEP_NEEDED` when the sign-in isn't fresh by the app's `passkeyAddFreshness`). `SessionSettings.PasskeyAddFreshness` ("session" or minutes) and `PasskeyAddDevOrigins`; `EmbedPasskeyPage` and `EmbedPasskeyDevOrigins` are retired (always false). See "Passkeys" in qAuth's docs (qAuth EXA-630).
- **0.17.0** (2026-11-28): `SessionSettings.EmbedPasskeyPage`: the app's pages may embed qAuth's add-a-passkey page (`/ui/passkeys/add`; off by default); `EmbedPasskeyDevOrigins`: its localhost origins too (development only). See "Add a passkey from your app" in qAuth's docs (qAuth EXA-625).
- **0.16.0** (2026-11-27): minting or revoking an organization's API key with your app's token (`APIKeys.Create`, `APIKeys.Revoke`) needs a recent sign-in to your app (the platform's `freshSignInMinutes`) or a step-up there, else 403 `FRESH_SIGN_IN_REQUIRED`; minting then asks the person to confirm it's them (`password`, `code`, `phoneCode`; 403 `CONFIRM_NEEDED`). Your app revokes only keys it minted (a Console key or another app's: 403). The key may use only your app's own APIs (403 otherwise), never qAuth's `qauth:org:*` scopes (403: make those in the Console), and `expiresAt` is required, at most the API's limit (default 90 days; 422). Keys carry `createdVia` (`appId`, `clientId`; null for Console keys), also in `ValidateKey` (qAuth EXA-627).
- **0.15.4** (2026-11-26): comments only: `Invite` on adding a member or creating a child now says what qAuth does: a new account is emailed a single-use link (7 days) to choose its password; no password is ever emailed or returned.
- **0.15.3** (2026-11-26): docs only: changes to how the person signs in (password, authenticator app, phone, passkeys, recovery codes) made with your app's token need a recent sign-in to your app with their own credentials (the platform's `freshSignInMinutes`) or a step-up there, else 403 `FRESH_SIGN_IN_REQUIRED`: send them to sign in again, then retry. A password in the request never stands in for it, and the token must be a JWT access token (opaque tokens can't). Personal tokens are made only in qAuth's own My account (Console, Portal): `tokens.create` with your app's token gets 403; list and revoke still work. Reads and sign-outs are not affected (qAuth EXA-489).
- **0.15.2** (2026-11-26): `SetupResult` names what an applied run made or uses: `APIID`, `Apps` (`FileID`, `ID`, `Name`, `ClientIDs`), `Issuer` and `IssuerReady`; `qauth apply --json` prints them.
- **0.15.1** (2026-11-26): each API has its own list of levels: `LevelRef` and `Levels` name that API's levels; `Org.LevelID` is always empty (deprecated) and `NewSubOrg.LevelID` is refused when set (give `Levels`); `LevelName` is the organization's level name when it is the same in every API. `MyOrg.InternalByLevel` says one of its levels is internal (`isInternal` stays its own flag).
- **0.15.0** (2026-11-26): "confirm it's you", one rule for every change to second steps: `Authenticator.Start(ctx,
  proof)` and `Phone.Add(ctx, phone, proof)` take a proof now; a person with an authenticator app confirms with
  their password AND a code (`Proof{Password, Code}`), others with their password. A missing part is a 403
  `CONFIRM_NEEDED`. Needs a qAuth server with it.
- **0.14.1** (2026-11-26): docs only: an organization key may have only qAuth scopes (`qauth:org:*`) and no API permission; such a key is for qAuth's organization routes and can't use your API.
- **0.14.0** (2026-11-26): instant sign-out. `Account.Sessions.Watch(ctx, sid, WatchOptions{ClientID})` keeps qAuth's
  session stream open and cancels a context the moment the session ends (any reason, any qAuth instance), with
  `SessionEnded(ctx)` saying why (`*SessionEndedError`; `ErrTokenRefused` when the token is no longer accepted); it
  reconnects with backoff and polls the state meanwhile. `SessionState.PollSeconds`; `Ended` also names
  `access_removed`, `suspended` and `replaced`.
- **0.13.0** (2026-11-26): the sign-in page and "verify again when the shared sign-in is reused" in an app's session
  settings and an organization's stricter override (`SigninForm`, `SkipChooser`, `SkipLastEmail`,
  `SkipPasskeyAutofill`, `EmailCodeSignIn`, `SkipCompanyByDomain`, `ReverifyOnReuse`: minutes as a JSON number, or
  `"always"`, `"never"`, `"default"`).
- **0.12.0** (2026-11-26): company sign-in and domains. `SSOSpec.PublicClient` (a client without a secret, PKCE, such
  as another qAuth tenant's web client), `SSOConnection.PublicClient`, `SSOState.OtherDirectoryApps` (apps the
  organization can use that sign in from another directory: company sign-in does not cover them), and
  `AddedDomain.TXTName` / `TXTValue` (the TXT record to publish).
- **0.11.0** (2026-11-26): child organizations from the parent. `NewSubOrg.ExternalID`; `SubOrgs.Create` takes
  `IdempotencyKey(key)` (a retry answers the same child; another request with the key is 409); `OrgClient.Rename`,
  `SetExternalID` and `SetLevels` (a direct child, from its parent: `org.suborgs.manage` / `org.suborgs.create`, or the
  parent's key with the new scope `qauth:org:suborgs`).
- **0.10.1** (2026-11-25): `Devices.SignOutAll` needs your device in `keep` (else 400; or `SignOutAllIncludingCurrent`);
  `Devices.List` marks `Current` only for the session passed.
- **0.10.0** (2026-11-25): the audit log. `AuditEntry` gains its own id (`UID`), who (`ActorType`, `ActorDisplay`, `ActingOrgID`), what
  (`TargetType`, `TargetName`, `Changes` before/after as `FieldChange`), the result (`Result`, `Reason`), where (`IP`,
  `UserAgent`, `RequestID`) and its place in the chain (`Seq`, `Hash`); `AuditQuery` takes the audit log's filters
  (`Group`, `Actor`, `Target`, `Result`, `App`, `IP`, `Request`, `From`, `To`); `Account.Activity` reads the person's
  own recent activity. Additions only.
- **0.9.0** (2026-11-25): `Devices.SignOutAll` keeps the calling device; `SignOutAllIncludingCurrent`;
  `SessionSettings.IdleByType` and `OrgSessionSettings.IdleByType` (idle per device type; TVs never idle by default).
- **0.8.0** (2026-11-25): sessions and devices. `Account.Devices`: `List`, `Update` (rename, mark shared),
  `SignOut`, `SignOutAll`, `PairingCode` (needs a recent sign-in), `Lookup` (Choices for number matching,
  OtherNetwork), `Approve(ctx, code, ApproveOptions{Number, ConfirmPlace, SignOut, ClientID})` / `Deny` (a TV's code); `Members.Devices` and
  `Members.EndDevice` (admins); `OrgClient.SessionSettings` / `SetSessionSettings` (stricter only).
- **0.7.0** (2026-11-25): app definition files. `SetupClient` (`NewSetupClient`, `Plan`, `Apply`,
  `SetupRequest`, `SetupResult`, `SetupPlan`, `SetupChange`, `SetupProblem`) and the `qauth` command
  (`cmd/qauth`: `qauth plan|apply [file] [--apply] [--prune] [--plan-hash H] [--json]`; names in the output
  escaped). Additions only.
- **0.6.0** (2026-11-25): a parent organization never manages a child's people (its people and keys see them
  read-only; adding, removing, resetting and giving roles in a child answer 403). `NewSubOrg.Invite` and
  `CreatedSubOrg.Invited`: a child's first admin may be anyone, you too (an existing account is added as it is; a new
  one is emailed, no password comes back); `RoleSpec.LevelID` and `AppRole.LevelID` (roles per level).
  `org.NewAdmin` is deprecated: setting a new admin is your tenant's. Additions only.
- **0.5.0** (2026-11-24): levels per product. `MyOrg` gains `ParentOrgID`, `LevelName`, `IsInternal` and
  `Levels` (API id -> your tenant's levels there, top first); `GivableRole` gains `LevelID`, `LevelName`,
  `BuiltIn` and `Reason`; `NewSubOrg.Levels`; `org.Levels` and `org.NewAdmin` (a child's direct parent sets its
  new admin: an existing member gets the roles, anyone else is invited by email; never a password),
  `NewAdminResult`. Additions only.
- **0.4.0** (2026-11-24): `org.Design`: the organization's sign-in page design (`Get`, `Set`, `Reset`,
  `AddPicture`), with the layout (simple or split, form at the start or end), form-side settings, side panel
  blocks and the platform's limits; `Branding` and `BrandingSpec` carry the `Design` too (a spec without it
  keeps the saved one).
- **0.3.0** (2026-11-24): new public module path `github.com/ExaCall-LLC/qauth-go` (MIT); same code as
  0.2.0. Change the import path; nothing else changed.
- **0.2.0** (2026-11-24): `FromIssuer(ctx, issuer, clientID, opts...)`: set up from your tenant's issuer and
  your app's client id alone. qAuth's API address is read once from the issuer's discovery document
  (`qauth_api`; the document must name the issuer, the address must be https, http only for localhost; no
  redirects), and a `Verifier` for that issuer and client is wired in (`WithVerifier`) unless you pass your
  own. The API address is pinned: `qauth_api` must be a trusted qAuth host (`DefaultTrustedAPIHosts`: auth.qapps.dev;
  `WithTrustedAPIHosts` for staging or your own qAuth; otherwise `UNTRUSTED_API`); a client you pass is used through a
  copy that never follows redirects. `WithAPIKey` + `Client.Org(id)` for machine calls with an organization's API key; `Client.Verifier()`
  and `Client.BaseURL()`. Needs a qAuth server with `qauth_api` in discovery (otherwise use `New` with its
  address). Nothing removed: `New`, `NewVerifier` and `WithKey` work as before.
- **0.1.0** (2026-11-24): first version. Offline token `Verifier` (issuers, clients, audiences,
  leeway, public-key algorithms only, ID tokens refused, key rotation, https only, no redirects), `net/http` `Middleware` / `OptionalMiddleware`,
  `Permissions` / `Can` / `Orgs` with a per-person cache, `ValidateKey` + `KeyMay` (cache optional),
  the person API (profile, orgs, permissions, tokens, account, sessions, step-up, verifications) and
  the organization API (members, invitations, roles, assignments, domains, API keys, company sign-in,
  child organizations, branding, audit), one `*Error` type.
