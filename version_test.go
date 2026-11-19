package revokegpt

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// One source, checked copies: Version, the top CHANGELOG entry, and the go line of go.mod agree with what the matrix tests.
func TestTheVersionAgreesWithTheChangelog(t *testing.T) {
	b, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^## (\S+)`).FindSubmatch(b)
	if m == nil || string(m[1]) != Version {
		t.Fatalf("CHANGELOG top entry %q, Version %q", m, Version)
	}
	if !regexp.MustCompile(`\A[0-9]+\.[0-9]+\.[0-9]+\z`).MatchString(Version) {
		t.Fatal(Version)
	}
}

// go.mod of the core and the firewall: next to each other in the monorepo (../integrations/go),
// under firewall/ in the public mirror.
func TestTheGoLineIs126(t *testing.T) {
	for _, alt := range [][]string{{"go.mod"}, {"../integrations/go/go.mod", "firewall/go.mod"}} {
		var b []byte
		var err error
		for _, f := range alt {
			if b, err = os.ReadFile(f); err == nil {
				break
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`(?m)^go (\S+)$`).FindSubmatch(b)
		if m == nil || (string(m[1]) != "1.26" && string(m[1]) != "1.26.0") {
			t.Errorf("%v: go line %q, want 1.26", alt, m)
		}
	}
}

func TestTheLicenseIsMIT(t *testing.T) {
	b, err := os.ReadFile("LICENSE")
	if err != nil || !strings.HasPrefix(string(b), "MIT License") {
		t.Fatalf("LICENSE: %v", err)
	}
}
