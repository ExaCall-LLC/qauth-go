// Command qauth plans and applies an app definition file (qauth.app.yaml)
// with a setup key, the same as `npx @isdlc.ai/qauth-cli`:
//
//	qauth plan [file]             # what would change (nothing is changed)
//	qauth apply [file]            # the same dry run
//	qauth apply [file] --apply    # make the changes
//	qauth apply [file] --apply --plan-hash <hash>   # only the reviewed plan
//
// Environment: QAUTH_SETUP_KEY (required), QAUTH_API_URL (default
// https://auth.qapps.dev). Flags: --apply, --prune, --plan-hash, --source,
// --path, --commit, --ref, --json, --format text|markdown. Exit codes: 0 done (dry run, applied, nothing to
// do), 1 refused or failed (the plan says why), 2 a usage or setup mistake
// (no key, no file, bad flag), 3 qAuth refused the key or could not be
// reached.
//
// Install: go install github.com/ExaCall-LLC/qauth-go/cmd/qauth@latest
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	qauth "github.com/ExaCall-LLC/qauth-go"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

const usage = `Usage: qauth plan|apply [file] [--apply] [--prune] [--json]
               [--source REPO] [--path PATH] [--commit SHA] [--ref REF]

Plans (dry run, the default) or applies an app definition file (qauth.app.yaml)
with a setup key. Needs QAUTH_SETUP_KEY; QAUTH_API_URL defaults to
https://auth.qapps.dev. Nothing is changed without --apply; nothing is removed
without --prune.
`

func run(args []string, env func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "plan" && args[0] != "apply") {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("qauth "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	doApply := fs.Bool("apply", false, "make the changes (default: dry run)")
	prune := fs.Bool("prune", false, "also remove what is in qAuth but not in the file, when safe")
	asJSON := fs.Bool("json", false, "print qAuth's answer as JSON")
	format := fs.String("format", "text", "text, or markdown (one fenced block, safe for a pull request comment)")
	source := fs.String("source", "", "where the file lives, e.g. github.com/acme/shop (default: from CI or git)")
	path := fs.String("path", "", "the file's path in the repository (default: the file argument)")
	commit := fs.String("commit", "", "the commit applied (default: from CI or git)")
	ref := fs.String("ref", "", "the branch or pull request (default: from CI)")
	planHash := fs.String("plan-hash", "", "apply only while the plan is this one (the hash a dry run printed)")
	// flags may come before or after the file
	var rest []string
	in := args[1:]
	for len(in) > 0 {
		if err := fs.Parse(in); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		rest = append(rest, fs.Arg(0))
		in = fs.Args()[1:]
	}
	if len(rest) > 1 {
		fmt.Fprintln(stderr, "qauth: one file at a time")
		return 2
	}
	file := "qauth.app.yaml"
	if len(rest) == 1 {
		file = rest[0]
	}
	if *format != "text" && *format != "markdown" {
		fmt.Fprintln(stderr, "qauth: --format is text or markdown")
		return 2
	}
	if cmd == "plan" && *doApply {
		fmt.Fprintln(stderr, "qauth: plan never changes anything; use: qauth apply --apply")
		return 2
	}
	key := strings.TrimSpace(env("QAUTH_SETUP_KEY"))
	if key == "" {
		fmt.Fprintln(stderr, "qauth: QAUTH_SETUP_KEY is not set (make a setup key in the qAuth Console: the API › Setup keys)")
		return 2
	}
	base := strings.TrimSpace(env("QAUTH_API_URL"))
	if base == "" {
		base = qauth.DefaultSetupURL
	}
	content, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(stderr, "qauth: can't read %s: %v\n", file, err)
		return 2
	}
	c, err := qauth.NewSetupClient(base, key, nil)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	origin := detect(env)
	req := qauth.SetupRequest{Content: string(content), Prune: *prune, Source: first(*source, origin.source), Path: first(*path, file),
		Commit: first(*commit, origin.commit), Ref: first(*ref, origin.ref), Runner: origin.runner, ExpectPlanHash: strings.TrimSpace(*planHash)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var res *qauth.SetupResult
	if *doApply {
		res, err = c.Apply(ctx, req)
	} else {
		res, err = c.Plan(ctx, req)
	}
	if err != nil {
		fmt.Fprintf(stderr, "qauth: %v\n", err)
		var e *qauth.Error
		if ok := asError(err, &e); ok && e.Status == 413 {
			return 1
		}
		return 3
	}
	switch {
	case *asJSON:
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(stdout, string(jsonSafe(b)))
	case *format == "markdown":
		fmt.Fprint(stdout, markdown(Render(res, base, file, *doApply)))
	default:
		fmt.Fprint(stdout, Render(res, base, file, *doApply))
	}
	if res.OK() {
		return 0
	}
	return 1
}

// Render prints a run the way both CLIs do.
func Render(res *qauth.SetupResult, base, file string, applied bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "qauth %s · %s · setup key %q\n", qauth.Version, safe(base), res.Key)
	if res.Summary != "" {
		fmt.Fprintf(&b, "Read %s: %s\n", safe(file), safe(res.Summary))
	}
	for _, p := range res.Problems {
		if p.Path != "" {
			fmt.Fprintf(&b, "  %s: %s\n", safe(p.Path), safe(p.Message))
		} else {
			fmt.Fprintf(&b, "  %s\n", safe(p.Message))
		}
	}
	if res.Text != "" {
		// one line at a time, each escaped: nothing in a name can fake a line
		for _, l := range strings.Split(strings.TrimRight(res.Text, "\n"), "\n") {
			b.WriteString(safe(l) + "\n")
		}
	}
	switch res.Result {
	case qauth.SetupApplied:
		if res.Message != "" {
			b.WriteString(safe(res.Message) + "\n")
		}
		fmt.Fprintf(&b, "Applied. Recorded in the activity log as run #%d.\n", res.Run)
	case qauth.SetupNoChanges:
		fmt.Fprintf(&b, "Recorded as run #%d.\n", res.Run)
	case qauth.SetupDryRun:
		fmt.Fprintf(&b, "Dry run recorded as run #%d.\n", res.Run)
	default:
		if res.Message != "" && len(res.Problems) == 0 {
			b.WriteString(safe(res.Message) + "\n")
		}
		fmt.Fprintf(&b, "%s. Recorded as run #%d.\n", safe(strings.ToUpper(res.Result[:1])+res.Result[1:]), res.Run)
	}
	return b.String()
}

func asError(err error, out **qauth.Error) bool {
	e, ok := err.(*qauth.Error)
	if ok {
		*out = e
	}
	return ok
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type origin struct{ source, commit, ref, runner string }

// detect reads where the file comes from: GitHub Actions, Woodpecker CI,
// or the local git checkout.
func detect(env func(string) string) origin {
	switch {
	case env("GITHUB_ACTIONS") == "true":
		o := origin{runner: "GitHub Actions", commit: env("GITHUB_SHA")}
		if repo := env("GITHUB_REPOSITORY"); repo != "" {
			o.source = hostOf(first(env("GITHUB_SERVER_URL"), "https://github.com")) + "/" + repo
		}
		o.ref = env("GITHUB_REF_NAME")
		if env("GITHUB_EVENT_NAME") == "pull_request" || env("GITHUB_EVENT_NAME") == "pull_request_target" {
			if n := strings.Split(strings.TrimPrefix(env("GITHUB_REF"), "refs/pull/"), "/")[0]; n != "" && n != env("GITHUB_REF") {
				o.ref = "pull request #" + n
			}
		}
		return o
	case env("CI") == "woodpecker" || env("CI_PIPELINE_NUMBER") != "" && env("CI_REPO") != "":
		o := origin{runner: "Woodpecker CI", commit: env("CI_COMMIT_SHA"), ref: env("CI_COMMIT_BRANCH")}
		if u := env("CI_REPO_URL"); u != "" {
			o.source = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://"), ".git")
		} else if repo := env("CI_REPO"); repo != "" {
			o.source = hostOf(env("CI_FORGE_URL")) + "/" + repo
		}
		if pr := env("CI_COMMIT_PULL_REQUEST"); pr != "" {
			o.ref = "pull request #" + pr
		}
		return o
	}
	o := origin{runner: "local"}
	if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
		o.commit = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("git", "config", "--get", "remote.origin.url").Output(); err == nil {
		o.source = repoName(strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD").Output(); err == nil {
		o.ref = strings.TrimSpace(string(out))
	}
	return o
}

func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	return strings.TrimRight(u, "/")
}

// repoName turns a git remote into host/owner/name (never credentials).
func repoName(remote string) string {
	r := strings.TrimSuffix(remote, ".git")
	if strings.HasPrefix(r, "git@") { // git@github.com:owner/name
		r = strings.Replace(strings.TrimPrefix(r, "git@"), ":", "/", 1)
	}
	r = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(r, "https://"), "http://"), "ssh://")
	if at := strings.LastIndex(r, "@"); at >= 0 && at < strings.Index(r+"/", "/") {
		r = r[at+1:] // user:token@host/…
	}
	return r
}

// unsafe: control (Cc), format (Cf: zero-width, direction marks, tag
// characters), line and paragraph separators (Zl, Zp).
func unsafe(r rune) bool {
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) || (r >= 0xE0000 && r <= 0xE007F)
}

// safe escapes those (and bytes that aren't UTF-8), so a name can never
// change how the output reads.
func safe(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unsafe(r):
			q := strconv.QuoteRuneToASCII(r)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// jsonSafe escapes those characters inside JSON as \uXXXX (still valid JSON).
func jsonSafe(b []byte) []byte {
	var out bytes.Buffer
	for _, r := range string(b) {
		if r != '\n' && unsafe(r) {
			for _, u := range utf16.Encode([]rune{r}) {
				fmt.Fprintf(&out, `\u%04x`, u)
			}
			continue
		}
		out.WriteRune(r)
	}
	return out.Bytes()
}

// markdown fences the output for a pull request comment: a fence longer
// than any run of backticks inside, mentions and links broken.
func markdown(text string) string {
	longest, run := 0, 0
	for _, r := range text {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	t := strings.NewReplacer("@", "@\u2060", "://", ":\u2060//", "](", "]\u2060(").Replace(text)
	return fence + "text\n" + strings.TrimRight(t, "\n") + "\n" + fence + "\n"
}
