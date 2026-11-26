package qauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// App definition files (qauth.app.yaml): CI plans and applies the file with
// a setup key (QAUTH_SETUP_KEY). qAuth reads the file and makes the plan; this
// client only sends it and returns the answer, so every tool shows the same
// plan. The `qauth` command (cmd/qauth) is built on it.

// DefaultSetupURL is where the CLIs send the file when QAUTH_API_URL is unset.
const DefaultSetupURL = "https://auth.qapps.dev"

// SetupClient plans and applies definition files with one setup key.
type SetupClient struct {
	base string
	key  string
	hc   *http.Client
}

// NewSetupClient makes a client for qAuth at baseURL (https; http only for
// localhost) with a setup key (qsk_…). hc may be nil (a 60 s timeout, no
// redirects).
func NewSetupClient(baseURL, setupKey string, hc *http.Client) (*SetupClient, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || !secureURL(u.String()) {
		return nil, fmt.Errorf("qauth: %q is not an https address (http only for localhost)", baseURL)
	}
	if !strings.HasPrefix(setupKey, "qsk_") {
		return nil, fmt.Errorf("qauth: the setup key must start with qsk_ (QAUTH_SETUP_KEY)")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second, CheckRedirect: noRedirect}
	}
	return &SetupClient{base: u.String(), key: setupKey, hc: hc}, nil
}

// SetupRequest is one run: the file and where it comes from.
type SetupRequest struct {
	Content string `json:"content"`
	Prune   bool   `json:"prune,omitempty"`
	Source  string `json:"source,omitempty"` // e.g. github.com/acme/shop
	Path    string `json:"path,omitempty"`   // e.g. qauth.app.yaml
	Commit  string `json:"commit,omitempty"`
	Ref     string `json:"ref,omitempty"`    // branch or pull request
	Runner  string `json:"runner,omitempty"` // e.g. GitHub Actions
	// ExpectPlanHash: apply only while the plan is this one (a dry run's
	// PlanHash, e.g. the plan reviewed on the pull request).
	ExpectPlanHash string `json:"expectPlanHash,omitempty"`
}

// SetupChange is one line of a plan: Op is + (add), ~ (change), - (remove),
// ! (warning: nothing happens), x (refused) or = (adopted: made in the
// Console, the same as the file, managed by the file from now on).
type SetupChange struct {
	Op         string   `json:"op"`
	Kind       string   `json:"kind"`
	Key        string   `json:"key"`
	Detail     string   `json:"detail,omitempty"`
	Dependants []string `json:"dependants,omitempty"`
}

// SetupPlan is what a run found.
type SetupPlan struct {
	API       string         `json:"api"`
	APIName   string         `json:"apiName"`
	Changes   []SetupChange  `json:"changes"`
	Added     int            `json:"added"`
	Changed   int            `json:"changed"`
	Removed   int            `json:"removed"`
	Refused   int            `json:"refused"`
	Adopted   int            `json:"adopted"`
	Unchanged map[string]int `json:"unchanged"`
}

// SetupProblem is one thing wrong with the file.
type SetupProblem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// Run results.
const (
	SetupDryRun    = "dry-run"
	SetupApplied   = "applied"
	SetupNoChanges = "no-changes"
	SetupRefused   = "refused"
	SetupFailed    = "failed"
)

// SetupResult is qAuth's answer to a run (refused and failed runs too).
type SetupResult struct {
	Run      int64     `json:"run"`
	Result   string    `json:"result"`
	Key      string    `json:"key"`
	Summary  string    `json:"summary,omitempty"`
	Plan     SetupPlan `json:"plan"`
	Text     string    `json:"text"`
	PlanHash string    `json:"planHash,omitempty"`
	// Markdown: Text as one fenced block, safe for a pull request comment.
	Markdown string         `json:"markdown,omitempty"`
	Problems []SetupProblem `json:"problems,omitempty"`
	Message  string         `json:"message,omitempty"`
	// After an applied (or no-changes) run: what it made or uses, so a
	// deployer gets {issuer, clientId, apiId} from one call. Issuer is set
	// but not ready yet when IssuerReady is false.
	APIID       string     `json:"apiId,omitempty"`
	Apps        []SetupApp `json:"apps,omitempty"`
	Issuer      string     `json:"issuer,omitempty"`
	IssuerReady bool       `json:"issuerReady,omitempty"`
	// Status is the HTTP status of the answer.
	Status int `json:"-"`
}

// SetupApp is one frontend of the file after a run: its id in the file,
// its qAuth id and name, and its sign-in clients' client ids.
type SetupApp struct {
	FileID    string   `json:"fileId"`
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	ClientIDs []string `json:"clientIds"`
}

// OK reports whether the run went through (a dry run, applied, or nothing to do).
func (r *SetupResult) OK() bool {
	return r.Result == SetupDryRun || r.Result == SetupApplied || r.Result == SetupNoChanges
}

// Plan compares the file with qAuth; nothing is changed.
func (c *SetupClient) Plan(ctx context.Context, req SetupRequest) (*SetupResult, error) {
	return c.run(ctx, "/setup/v1/plan", req)
}

// Apply makes the plan's changes (all or nothing while anything is refused).
func (c *SetupClient) Apply(ctx context.Context, req SetupRequest) (*SetupResult, error) {
	return c.run(ctx, "/setup/v1/apply", req)
}

// run returns the run for every answer that carries one (refused, invalid
// and failed runs too); an *Error otherwise (key refused, file too large,
// qAuth out of reach).
func (c *SetupClient) run(ctx context.Context, path string, req SetupRequest) (*SetupResult, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Authorization", "Bearer "+c.key)
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("User-Agent", "qauth-go/"+Version)
	resp, err := c.hc.Do(hr)
	if err != nil {
		return nil, &Error{Code: CodeUnavailable, Message: "qAuth could not be reached at " + c.base, Err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, &Error{Status: resp.StatusCode, Code: CodeUnavailable, Message: "qAuth's answer could not be read", Err: err}
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, &Error{Status: resp.StatusCode, Code: CodeUnavailable, Message: fmt.Sprintf("qAuth answered HTTP %d without a JSON envelope (is QAUTH_API_URL qAuth's address?)", resp.StatusCode)}
	}
	var res SetupResult
	if len(env.Data) > 0 && string(env.Data) != "null" {
		if err := json.Unmarshal(env.Data, &res); err == nil && res.Result != "" {
			res.Status = resp.StatusCode
			return &res, nil
		}
	}
	e := &Error{Status: resp.StatusCode, Code: "HTTP_" + fmt.Sprint(resp.StatusCode), Message: env.Message, RequestID: env.Meta.RequestID}
	if env.Error != nil {
		e.Code, e.Message, e.Fields = env.Error.Code, env.Error.Message, env.Error.Fields
	}
	return nil, e
}
