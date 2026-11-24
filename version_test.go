package qauth

import (
	"os"
	"regexp"
	"testing"
)

// The newest entry of the README's Changes is this Version.
func TestVersionMatchesREADME(t *testing.T) {
	b, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^## Changes\s+- \*\*([0-9]+\.[0-9]+\.[0-9]+)\*\*`).FindSubmatch(b)
	if m == nil || string(m[1]) != Version {
		t.Fatalf("README's newest change is %q, Version is %q", m, Version)
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(Version) {
		t.Fatalf("Version %q is not semver", Version)
	}
}
