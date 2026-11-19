package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// The arbiter: packages/protocol/test-vectors/policy.json. Every row of every section must pass.
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

type vectorFile struct {
	Suite           string            `json:"suite"`
	ProtocolVersion int               `json:"protocolVersion"`
	NowDefault      int64             `json:"nowDefault"`
	Normalize       []json.RawMessage `json:"normalize"`
	Glob            []json.RawMessage `json:"glob"`
	Host            []json.RawMessage `json:"host"`
	Decide          []json.RawMessage `json:"decide"`
	Bundle          []json.RawMessage `json:"bundle"`
	Session         []json.RawMessage `json:"session"`
	Headers         []json.RawMessage `json:"headers"`
	ReturnPath      []json.RawMessage `json:"returnPath"`
	Fixtures        struct {
		Bundles     map[string]json.RawMessage `json:"bundles"`
		Unvalidated map[string]json.RawMessage `json:"unvalidated"`
	} `json:"fixtures"`
}

func loadVectors(t testing.TB) *vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if v.Suite != "policy" || v.ProtocolVersion != 1 {
		t.Fatalf("unexpected vector header %q %d", v.Suite, v.ProtocolVersion)
	}
	return &v
}

func decodeRow(t *testing.T, raw json.RawMessage, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode row: %v", err)
	}
}

func TestVectorsNormalize(t *testing.T) {
	v := loadVectors(t)
	n := 0
	for _, raw := range v.Normalize {
		var c struct {
			Name     string `json:"name"`
			Input    string `json:"input"`
			Expected struct {
				OK        bool   `json:"ok"`
				Path      string `json:"path"`
				Collapsed string `json:"collapsed"`
				Reason    string `json:"reason"`
				Detail    string `json:"detail"`
			} `json:"expected"`
		}
		decodeRow(t, raw, &c)
		n++
		t.Run(c.Name, func(t *testing.T) {
			got := Normalize(c.Input)
			if got.OK != c.Expected.OK {
				t.Fatalf("ok = %v, want %v (%+v)", got.OK, c.Expected.OK, got)
			}
			if got.OK {
				if got.Path != c.Expected.Path || got.Collapsed != c.Expected.Collapsed {
					t.Fatalf("got path %q collapsed %q, want %q %q", got.Path, got.Collapsed, c.Expected.Path, c.Expected.Collapsed)
				}
				return
			}
			if got.Reason != c.Expected.Reason || got.Detail != c.Expected.Detail {
				t.Fatalf("got %s/%s, want %s/%s", got.Reason, got.Detail, c.Expected.Reason, c.Expected.Detail)
			}
		})
	}
	t.Logf("normalize rows: %d", n)
}

func TestVectorsGlob(t *testing.T) {
	v := loadVectors(t)
	sawBudget := false
	for _, raw := range v.Glob {
		var c struct {
			Name     string  `json:"name"`
			Pattern  string  `json:"pattern"`
			Path     string  `json:"path"`
			Target   *string `json:"target"`
			Compiles *bool   `json:"compiles"`
			Matches  bool    `json:"matches"`
			BudgetMs *int    `json:"budgetMs"`
		}
		decodeRow(t, raw, &c)
		if c.BudgetMs != nil && *c.BudgetMs == 5 {
			sawBudget = true
		}
		t.Run(c.Name, func(t *testing.T) {
			g := CompileGlob(c.Pattern)
			if c.Compiles != nil && !*c.Compiles {
				if g != nil {
					t.Fatalf("pattern %q compiled, want nil", c.Pattern)
				}
				return
			}
			if g == nil {
				t.Fatalf("pattern %q did not compile", c.Pattern)
			}
			start := time.Now()
			path := c.Path
			if c.Target != nil {
				n := Normalize(*c.Target)
				if !n.OK {
					t.Fatalf("target %q did not normalise", *c.Target)
				}
				path = n.Collapsed
			}
			if got := GlobMatch(g, path); got != c.Matches {
				t.Fatalf("match(%q, %q) = %v, want %v", c.Pattern, path, got, c.Matches)
			}
			if c.BudgetMs != nil && time.Since(start) > time.Duration(*c.BudgetMs)*time.Millisecond {
				t.Fatalf("match took %v, budget %d ms", time.Since(start), *c.BudgetMs)
			}
		})
	}
	if !sawBudget {
		t.Fatal("no 5 ms budget row")
	}
}

func TestVectorsHost(t *testing.T) {
	v := loadVectors(t)
	for _, raw := range v.Host {
		var c struct {
			Name    string `json:"name"`
			Pattern string `json:"pattern"`
			Host    string `json:"host"`
			Matches bool   `json:"matches"`
		}
		decodeRow(t, raw, &c)
		t.Run(c.Name, func(t *testing.T) {
			if got := HostMatches(c.Pattern, c.Host); got != c.Matches {
				t.Fatalf("HostMatches(%q, %q) = %v, want %v", c.Pattern, c.Host, got, c.Matches)
			}
		})
	}
}

func TestVectorsDecide(t *testing.T) {
	v := loadVectors(t)
	bundles := map[string]*Payload{}
	for _, set := range []map[string]json.RawMessage{v.Fixtures.Bundles, v.Fixtures.Unvalidated} {
		for name, raw := range set {
			p, err := ParsePayload(raw)
			if err != nil {
				t.Fatalf("fixture %s does not parse: %v", name, err)
			}
			bundles[name] = p
		}
	}
	kinds := map[string]bool{}
	for _, raw := range v.Decide {
		var c struct {
			Name    string  `json:"name"`
			Bundle  string  `json:"bundle"`
			Request Request `json:"request"`
			Session struct {
				Kind string `json:"kind"`
				Lvl  int    `json:"lvl"`
				Sc   int    `json:"sc"`
			} `json:"session"`
			Verify *struct {
				Kind   string  `json:"kind"`
				Score  float64 `json:"score"`
				Reason string  `json:"reason"`
			} `json:"verify"`
			Now      *int64          `json:"now"`
			Expected json.RawMessage `json:"expected"`
		}
		decodeRow(t, raw, &c)
		t.Run(c.Name, func(t *testing.T) {
			b := bundles[c.Bundle]
			if b == nil {
				t.Fatalf("fixture %q missing", c.Bundle)
			}
			now := v.NowDefault
			if c.Now != nil {
				now = *c.Now
			}
			sess := SessionState{Kind: c.Session.Kind, Lvl: c.Session.Lvl, Sc: c.Session.Sc}
			var out *VerifyOutcome
			if c.Verify != nil {
				out = &VerifyOutcome{Kind: c.Verify.Kind, Score: c.Verify.Score, Reason: c.Verify.Reason}
			}
			got := Decide(b, c.Request, sess, out, now)
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var g, w any
			_ = json.Unmarshal(gotJSON, &g)
			_ = json.Unmarshal(c.Expected, &w)
			if !reflect.DeepEqual(g, w) {
				t.Fatalf("got  %s\nwant %s", gotJSON, c.Expected)
			}
			kinds[got.Kind] = true
		})
	}
	for _, k := range []string{"allow", "block", "challenge", "redirect", "needs-verify"} {
		if !kinds[k] {
			t.Errorf("no decide row produced kind %s", k)
		}
	}
}

type keyRow struct {
	Kid      string `json:"kid"`
	Alg      string `json:"alg"`
	Pub      string `json:"pub"`
	NotAfter int64  `json:"notAfter"`
}

func (k keyRow) key() Key { return Key{Kid: k.Kid, Alg: k.Alg, Pub: k.Pub, NotAfter: k.NotAfter} }

func keysOf(rows []keyRow) []Key {
	out := make([]Key, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.key())
	}
	return out
}

func TestVectorsBundle(t *testing.T) {
	v := loadVectors(t)
	sawNonCanonicalS := false
	for _, raw := range v.Bundle {
		var c struct {
			Name       string   `json:"name"`
			Served     string   `json:"served"`
			Pinned     []keyRow `json:"pinned"`
			Now        int64    `json:"now"`
			MinVersion int64    `json:"minVersion"`
			Expect     struct {
				SiteID  string `json:"siteId"`
				SiteKey string `json:"siteKey"`
			} `json:"expect"`
			Expected struct {
				OK      bool   `json:"ok"`
				Version int64  `json:"version"`
				Reason  string `json:"reason"`
			} `json:"expected"`
		}
		decodeRow(t, raw, &c)
		if c.Name == "sig-non-canonical-s" {
			sawNonCanonicalS = true
		}
		t.Run(c.Name, func(t *testing.T) {
			r := VerifyBundle(c.Served, keysOf(c.Pinned), c.Now, c.MinVersion,
				BundleExpect{SiteID: c.Expect.SiteID, SiteKey: c.Expect.SiteKey})
			if r.OK != c.Expected.OK {
				t.Fatalf("ok = %v (reason %q), want %v (%q)", r.OK, r.Reason, c.Expected.OK, c.Expected.Reason)
			}
			if r.OK {
				if r.Payload.Version != c.Expected.Version {
					t.Fatalf("version %d, want %d", r.Payload.Version, c.Expected.Version)
				}
				return
			}
			if r.Reason != c.Expected.Reason {
				t.Fatalf("reason %q, want %q", r.Reason, c.Expected.Reason)
			}
		})
	}
	if !sawNonCanonicalS {
		t.Fatal("sig-non-canonical-s row missing")
	}
}

func TestVectorsSession(t *testing.T) {
	v := loadVectors(t)
	for _, raw := range v.Session {
		var c struct {
			Name   string   `json:"name"`
			Token  *string  `json:"token"`
			Keys   []keyRow `json:"keys"`
			Expect struct {
				SiteID string `json:"siteId"`
				Host   string `json:"host"`
			} `json:"expect"`
			B struct {
				MinIat     int64    `json:"minIat"`
				RevokedJti []string `json:"revokedJti"`
			} `json:"b"`
			Now      int64 `json:"now"`
			Expected struct {
				Kind string `json:"kind"`
				Lvl  int    `json:"lvl"`
				Sc   int    `json:"sc"`
			} `json:"expected"`
		}
		decodeRow(t, raw, &c)
		t.Run(c.Name, func(t *testing.T) {
			token := ""
			if c.Token != nil {
				token = *c.Token
			}
			got := VerifySession(token, keysOf(c.Keys),
				SessionExpect{SiteID: c.Expect.SiteID, Host: c.Expect.Host},
				SessionBounds{MinIat: c.B.MinIat, RevokedJti: c.B.RevokedJti}, c.Now)
			if got.Kind != c.Expected.Kind {
				t.Fatalf("kind %q, want %q", got.Kind, c.Expected.Kind)
			}
			if got.Kind == "valid" && (got.Lvl != c.Expected.Lvl || got.Sc != c.Expected.Sc) {
				t.Fatalf("lvl/sc %d/%d, want %d/%d", got.Lvl, got.Sc, c.Expected.Lvl, c.Expected.Sc)
			}
		})
	}
}

func TestVectorsHeaders(t *testing.T) {
	v := loadVectors(t)
	for _, raw := range v.Headers {
		var c struct {
			Name     string   `json:"name"`
			Names    []string `json:"names"`
			Expected []string `json:"expected"`
		}
		decodeRow(t, raw, &c)
		t.Run(c.Name, func(t *testing.T) {
			got := StripRgHeaders(c.Names)
			if len(got) == 0 && len(c.Expected) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.Expected) {
				t.Fatalf("got %v, want %v", got, c.Expected)
			}
		})
	}
}

func TestVectorsReturnPath(t *testing.T) {
	v := loadVectors(t)
	for _, raw := range v.ReturnPath {
		var c struct {
			Name string `json:"name"`
			Path string `json:"path"`
			Safe bool   `json:"safe"`
		}
		decodeRow(t, raw, &c)
		t.Run(c.Name, func(t *testing.T) {
			if got := IsSafeReturnPath(c.Path); got != c.Safe {
				t.Fatalf("IsSafeReturnPath(%q) = %v, want %v", c.Path, got, c.Safe)
			}
		})
	}
}

// FuzzNormalize seeds from the normalize rows. Properties: never panics; a successful result is
// ASCII-only, starts with "/", holds none of ? # \ ; or a raw control or space; the collapsed form
// has no "//" and is a fixed point of Normalize.
func FuzzNormalize(f *testing.F) {
	v := loadVectors(f)
	for _, raw := range v.Normalize {
		var c struct {
			Input string `json:"input"`
		}
		_ = json.Unmarshal(raw, &c)
		f.Add(c.Input)
	}
	f.Add("/admin%2Fsecret")
	f.Add("/%2e%2e/admin")
	f.Add("/%C0%AF")
	f.Fuzz(func(t *testing.T, in string) {
		n := Normalize(in)
		if !n.OK {
			if n.Reason != "invalid" && n.Reason != "non-canonical" {
				t.Fatalf("bad reason %q", n.Reason)
			}
			return
		}
		for _, s := range []string{n.Path, n.Collapsed} {
			if s == "" || s[0] != '/' {
				t.Fatalf("result %q does not start with /", s)
			}
			for i := 0; i < len(s); i++ {
				c := s[i]
				if c <= 0x20 || c >= 0x7f || c == '?' || c == '#' || c == '\\' || c == ';' {
					t.Fatalf("result %q holds byte 0x%02x", s, c)
				}
			}
		}
		for i := 0; i+1 < len(n.Collapsed); i++ {
			if n.Collapsed[i] == '/' && n.Collapsed[i+1] == '/' {
				t.Fatalf("collapsed %q holds //", n.Collapsed)
			}
		}
		// The collapsed form is a fixed point (the path form is not: one trailing slash is dropped
		// per pass, so "/a//" gives "/a/").
		// (Escapes can grow the path past the 8 KiB limit on the second pass; skip those.)
		if len(n.Collapsed) > maxRawPathBytes {
			return
		}
		again := Normalize(n.Collapsed)
		if !again.OK || again.Path != n.Collapsed || again.Collapsed != n.Collapsed {
			t.Fatalf("collapsed not idempotent: %q -> %q -> %+v", in, n.Collapsed, again)
		}
	})
}
