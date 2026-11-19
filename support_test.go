package revokegpt

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// vectorsDir finds packages/protocol/test-vectors (in the mirror: vectors/) by walking up from the package directory.
func vectorsDir(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		p := filepath.Join(dir, "packages", "protocol", "test-vectors")
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
		// The public mirror carries the suites in vectors/ at its root.
		if _, err := os.Stat(filepath.Join(dir, "vectors", "keys.json")); err == nil {
			return filepath.Join(dir, "vectors")
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("packages/protocol/test-vectors not found above " + dir)
	return ""
}

func loadVector(t testing.TB, name string) vectorFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorsDir(t), name))
	if err != nil {
		t.Fatalf("a required vector file is missing: %v", err)
	}
	var f vectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

type vectorFile struct {
	Suite  string `json:"suite"`
	Cases  []vectorCase
	Suites []struct {
		File   string `json:"file"`
		Server string `json:"server"`
	} `json:"suites"`
}

type vectorCase = map[string]any

func (f *vectorFile) UnmarshalJSON(b []byte) error {
	type plain struct {
		Suite  string       `json:"suite"`
		Cases  []vectorCase `json:"cases"`
		Suites []struct {
			File   string `json:"file"`
			Server string `json:"server"`
		} `json:"suites"`
	}
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	f.Suite, f.Cases, f.Suites = p.Suite, p.Cases, p.Suites
	return nil
}

// fixtureSecret is the published valid secret key of keys.json.
func fixtureSecret(t testing.TB) string {
	t.Helper()
	for _, c := range loadVector(t, "keys.json").Cases {
		in, _ := c["input"].(map[string]any)
		ex, _ := c["expected"].(map[string]any)
		if ex["valid"] == true && ex["kind"] == "secret" {
			return in["key"].(string)
		}
	}
	t.Fatal("keys.json has no valid secret key")
	return ""
}

const testEndpoint = "https://api.revokegpt.test/v1/siteverify"

// stub is a recording RoundTripper that serves handler(request) and counts the calls.
type stub struct {
	mu      sync.Mutex
	handler func(*http.Request) (*http.Response, error)
	reqs    []*http.Request
	bodies  []string
}

func (s *stub) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
	}
	s.mu.Lock()
	s.reqs = append(s.reqs, r)
	s.bodies = append(s.bodies, string(body))
	s.mu.Unlock()
	return s.handler(r)
}

func (s *stub) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

func respond(status int, body string) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Status:     http.StatusText(status),
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(bytes.NewReader([]byte(body))),
			Request:    r,
		}, nil
	}
}

func stubClient(t testing.TB, s *stub, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{WithHTTPClient(&http.Client{Transport: s})}, opts...)
	c, err := New(fixtureSecret(t), testEndpoint, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
