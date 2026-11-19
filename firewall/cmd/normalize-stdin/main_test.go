package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var vectorsPath = findPolicyVectors()

// findPolicyVectors walks up from the package directory to packages/protocol/test-vectors/policy.json (in the public
// mirror: vectors/policy.json at the repository root).
func findPolicyVectors() string {
	dir, _ := os.Getwd()
	for i := 0; i < 10; i++ {
		for _, p := range []string{filepath.Join(dir, "packages", "protocol", "test-vectors", "policy.json"), filepath.Join(dir, "vectors", "policy.json")} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		dir = filepath.Dir(dir)
	}
	return "policy.json not found"
}

// Every normalize row of the shared vectors, piped through run(), gives the expected JSON.
// Rows whose input holds a newline cannot travel one-per-line and are skipped (they are covered
// by TestVectorsNormalize in the library).
func TestRunMatchesVectors(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Normalize []struct {
			Name     string         `json:"name"`
			Input    string         `json:"input"`
			Expected map[string]any `json:"expected"`
		} `json:"normalize"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var in bytes.Buffer
	var kept []int
	for i, c := range v.Normalize {
		if strings.ContainsRune(c.Input, '\n') {
			continue
		}
		in.WriteString(c.Input + "\n")
		kept = append(kept, i)
	}
	var out bytes.Buffer
	if err := run(&in, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != len(kept) {
		t.Fatalf("%d output lines for %d inputs", len(lines), len(kept))
	}
	for j, i := range kept {
		c := v.Normalize[i]
		var got map[string]any
		if err := json.Unmarshal([]byte(lines[j]), &got); err != nil {
			t.Fatalf("%s: %v: %q", c.Name, err, lines[j])
		}
		for k, want := range c.Expected {
			if got[k] != want {
				t.Errorf("%s: %s = %v, want %v", c.Name, k, got[k], want)
			}
		}
		if len(got) != len(c.Expected) {
			t.Errorf("%s: fields %v, want %v", c.Name, got, c.Expected)
		}
	}
}

func TestRunOutputShapeAndEdges(t *testing.T) {
	var out bytes.Buffer
	// No trailing newline on the last line; an empty line is a target too; "<" is not escaped.
	if err := run(strings.NewReader("/a<b\n\n/x//y"), &out); err != nil {
		t.Fatal(err)
	}
	want := `{"ok":true,"path":"/a%3Cb","collapsed":"/a%3Cb"}` + "\n" +
		`{"ok":false,"reason":"invalid","detail":"not-origin-form"}` + "\n" +
		`{"ok":true,"path":"/x//y","collapsed":"/x/y"}` + "\n"
	if out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", out.String(), want)
	}
	out.Reset()
	if err := run(strings.NewReader("/a\r\n"), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != `{"ok":false,"reason":"invalid","detail":"control-character"}`+"\n" {
		t.Fatalf("CR line: %s", out.String())
	}
}
