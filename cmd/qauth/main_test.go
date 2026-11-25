package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeQAuth answers like qAuth's /setup/v1 routes and keeps what it got.
func fakeQAuth(t *testing.T, status int, result string) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer qsk_"+strings.Repeat("k", 40) {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"The setup key is not valid","data":null,"error":{"code":"UNAUTHORIZED","message":"The setup key is not valid"},"meta":{}}`))
			return
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		in["_path"] = r.URL.Path
		got = append(got, in)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": status < 400, "status": status, "message": "m", "meta": map[string]any{},
			"data": map[string]any{"run": 12, "result": result, "key": "qcdn-ci", "summary": "api qcdn, 3 levels", "text": "Plan for \"qCDN API\" (qcdn)\n", "plan": map[string]any{"api": "qcdn"}}})
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func file(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "qauth.app.yaml")
	if err := os.WriteFile(p, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestCLI(t *testing.T) {
	srv, got := fakeQAuth(t, 200, "dry-run")
	f := file(t)
	env := map[string]string{"QAUTH_SETUP_KEY": "qsk_" + strings.Repeat("k", 40), "QAUTH_API_URL": srv.URL,
		"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "ExaCall-LLC/qcdn", "GITHUB_SHA": "a41c9e2ff", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/48/merge"}
	var out, errb bytes.Buffer
	// dry run by default, flags after the file
	if code := run([]string{"apply", f, "--prune"}, envOf(env), &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	g := (*got)[0]
	if g["_path"] != "/setup/v1/plan" || g["prune"] != true || g["source"] != "github.com/ExaCall-LLC/qcdn" || g["commit"] != "a41c9e2ff" || g["ref"] != "pull request #48" || g["runner"] != "GitHub Actions" || g["content"] != "version: 1\n" {
		t.Fatalf("sent %v", g)
	}
	if !strings.Contains(out.String(), `setup key "qcdn-ci"`) || !strings.Contains(out.String(), "Plan for \"qCDN API\" (qcdn)") || !strings.Contains(out.String(), "Dry run recorded as run #12") {
		t.Fatalf("printed:\n%s", out.String())
	}
	// --apply
	if code := run([]string{"apply", "--apply", f, "--commit", "c0ffee"}, envOf(env), &out, &errb); code != 0 || (*got)[1]["_path"] != "/setup/v1/apply" || (*got)[1]["commit"] != "c0ffee" {
		t.Fatalf("apply: %d %v", code, (*got)[1])
	}
	// --json
	out.Reset()
	if code := run([]string{"plan", f, "--json"}, envOf(env), &out, &errb); code != 0 || !json.Valid(out.Bytes()) {
		t.Fatalf("json: %d %s", code, out.String())
	}
	// mistakes: 2
	for name, c := range map[string][]string{"no command": {}, "plan --apply": {"plan", f, "--apply"}, "no file": {"apply", "/nope/qauth.app.yaml"}, "bad flag": {"apply", "--force"}} {
		if code := run(c, envOf(env), &out, &errb); code != 2 {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	if code := run([]string{"plan", f}, envOf(map[string]string{"QAUTH_API_URL": srv.URL}), &out, &errb); code != 2 || !strings.Contains(errb.String(), "QAUTH_SETUP_KEY") {
		t.Fatalf("no key: %d", code)
	}
	// a key qAuth refuses, or qAuth out of reach: 3
	bad := map[string]string{"QAUTH_SETUP_KEY": "qsk_" + strings.Repeat("x", 40), "QAUTH_API_URL": srv.URL}
	if code := run([]string{"plan", f}, envOf(bad), &out, &errb); code != 3 {
		t.Fatalf("refused key: %d", code)
	}
	gone := map[string]string{"QAUTH_SETUP_KEY": env["QAUTH_SETUP_KEY"], "QAUTH_API_URL": "http://127.0.0.1:1"}
	if code := run([]string{"plan", f}, envOf(gone), &out, &errb); code != 3 {
		t.Fatalf("unreachable: %d", code)
	}
}

// A refused run exits 1 and still prints the plan.
func TestCLIRefused(t *testing.T) {
	srv, _ := fakeQAuth(t, 409, "refused")
	var out, errb bytes.Buffer
	env := map[string]string{"QAUTH_SETUP_KEY": "qsk_" + strings.Repeat("k", 40), "QAUTH_API_URL": srv.URL}
	if code := run([]string{"apply", file(t), "--apply"}, envOf(env), &out, &errb); code != 1 || !strings.Contains(out.String(), `Plan for "qCDN API"`) || !strings.Contains(out.String(), "Refused. Recorded as run #12") {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
}

func TestOrigin(t *testing.T) {
	o := detect(envOf(map[string]string{"CI": "woodpecker", "CI_REPO_URL": "https://git.example.test/acme/qcdn", "CI_COMMIT_SHA": "abc", "CI_COMMIT_PULL_REQUEST": "7", "CI_PIPELINE_NUMBER": "3", "CI_REPO": "acme/qcdn"}))
	if o.runner != "Woodpecker CI" || o.source != "git.example.test/acme/qcdn" || o.ref != "pull request #7" || o.commit != "abc" {
		t.Fatalf("woodpecker = %+v", o)
	}
	for remote, want := range map[string]string{
		"git@github.com:ExaCall-LLC/qcdn.git":             "github.com/ExaCall-LLC/qcdn",
		"https://user:secret@github.com/ExaCall-LLC/qcdn": "github.com/ExaCall-LLC/qcdn",
		"https://github.com/ExaCall-LLC/qcdn.git":         "github.com/ExaCall-LLC/qcdn",
		"ssh://git@git.example.test:2222/acme/qcdn.git":   "git.example.test:2222/acme/qcdn",
	} {
		if got := repoName(remote); got != want {
			t.Errorf("%s -> %s, want %s", remote, got, want)
		}
	}
}

// Names can't fake lines in the output; --plan-hash is sent.
func TestCLIEscapesAndPlanHash(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "status": 200, "meta": map[string]any{},
			"data": map[string]any{"run": 1, "result": "applied", "key": "k\nApplied. Recorded", "summary": "api x\u202e", "text": "Plan for \"X\" (x)\n  + role \"a\u202eb\"\n", "message": "m\r\n+ fake"}})
	}))
	defer srv.Close()
	var out, errb bytes.Buffer
	env := map[string]string{"QAUTH_SETUP_KEY": "qsk_" + strings.Repeat("k", 40), "QAUTH_API_URL": srv.URL}
	if code := run([]string{"apply", file(t), "--apply", "--plan-hash", "abc123"}, envOf(env), &out, &errb); code != 0 {
		t.Fatalf("exit %d %s", code, errb.String())
	}
	if got["expectPlanHash"] != "abc123" {
		t.Fatalf("sent %v", got)
	}
	o := out.String()
	if strings.Contains(o, "\u202e") || strings.Contains(o, "\r") || strings.Contains(o, "\n+ fake") || !strings.Contains(o, `\u202e`) {
		t.Fatalf("not escaped:\n%q", o)
	}
}

// --format markdown: one fence nothing inside can close, no mentions or
// links; --json escapes format characters coming from names.
func TestCLIMarkdownAndJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "status": 200, "meta": map[string]any{},
			"data": map[string]any{"run": 1, "result": "dry-run", "key": "k", "text": "Plan for \"X\" (x)\n  + role \"```` @team [a](https://evil.test) \u202e\"\n"}})
	}))
	defer srv.Close()
	env := map[string]string{"QAUTH_SETUP_KEY": "qsk_" + strings.Repeat("k", 40), "QAUTH_API_URL": srv.URL}
	var out, errb bytes.Buffer
	if code := run([]string{"plan", file(t), "--format", "markdown"}, envOf(env), &out, &errb); code != 0 {
		t.Fatalf("exit %d %s", code, errb.String())
	}
	md := out.String()
	if !strings.HasPrefix(md, "`````text\n") || !strings.HasSuffix(md, "`````\n") || strings.Contains(md, "@team") || strings.Contains(md, "https://evil") {
		t.Fatalf("markdown:\n%s", md)
	}
	out.Reset()
	if code := run([]string{"plan", file(t), "--json"}, envOf(env), &out, &errb); code != 0 || strings.ContainsRune(out.String(), 0x202e) || !json.Valid(out.Bytes()) {
		t.Fatalf("json: %q", out.String())
	}
	if code := run([]string{"plan", file(t), "--format", "html"}, envOf(env), &out, &errb); code != 2 {
		t.Fatal("bad format")
	}
}
