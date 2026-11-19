package revokegpt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every file the shared manifest requires of a server SDK is loaded by a test of this SDK: the core module's own
// tests.
func TestEveryRequiredSuiteIsRunByATest(t *testing.T) {
	var sources []string
	for _, dir := range []string{"."} {
		files, _ := filepath.Glob(filepath.Join(dir, "*_test.go"))
		for _, f := range files {
			if filepath.Base(f) == "manifest_test.go" {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			sources = append(sources, string(b))
		}
	}
	required := 0
	for _, s := range loadVector(t, "sdk-conformance.json").Suites {
		if s.Server != "required" {
			continue
		}
		required++
		found := false
		for _, src := range sources {
			if strings.Contains(src, `"`+s.File+`"`) || strings.Contains(src, `"`+strings.TrimSuffix(s.File, ".json")+`.json"`) {
				found = true
			}
		}
		if !found {
			t.Errorf("no test loads %s", s.File)
		}
	}
	if required != 9 {
		t.Fatalf("%d required suites", required)
	}
}
