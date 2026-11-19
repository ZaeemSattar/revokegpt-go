package firewall

import (
	"os"
	"strings"
	"testing"

	"github.com/ZaeemSattar/revokegpt-go/hostname"
)

// Golden values come from running the reference (canonicalizeHostname via requestHost) on the
// same inputs. Characters outside the accepted letter set are refused (a 400), never mapped to a
// different host.
func TestCanonicalHostGolden(t *testing.T) {
	golden := map[string]string{
		"EXAMPLE.com":           "example.com",
		"example.com.":          "example.com",
		"example.com:8443":      "example.com",
		"07.07":                 "7.0.0.7",
		"07.07.0X1":             "7.7.0.1",
		"256":                   "0.0.1.0",
		"0x":                    "0.0.0.0",
		"0x7f.1":                "127.0.0.1",
		"127.0.0.1:3000":        "127.0.0.1",
		"ß":                     "xn--zca",
		"日本.example":            "xn--wgv71a.example",
		"ÀÉ.example":            "xn--0cas.example",
		"カタカナ.example":          "xn--lcka3d1b.example",
		"łódź.example":          "xn--d-uga0v4h.example",
		"XN--BCHER-KVA.example": "xn--bcher-kva.example",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"bücher.example":        "xn--bcher-kva.example",
		"BÜCHER.example":        "xn--bcher-kva.example",
	}
	for in, want := range golden {
		got, ok := RequestHost(in)
		if !ok || got != want {
			t.Errorf("RequestHost(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{
		"", "example.com:", "example.com:99999", "example.com:80:80", "[::1]", "a@b.com", "a b.com",
		"4294967296", "1.2.3.4.5", "_x.com", "-a.com", "a-.com", "a..b",
		"xn--a.example", "xn--bcher-kva-.example", "xn--zca-.example",
		"ǆ.example", "İ.example", "ｅxample.com", "a­.com", "ẍ.com", "ﬁ.com",
	} {
		if got, ok := RequestHost(in); ok {
			t.Errorf("RequestHost(%q) = %q, want refusal", in, got)
		}
	}
}

// The firewall's hostname functions are the SDK's: the same answers on every input, and no copy of the code here.
func TestHostnameFunctionsAreTheSDKs(t *testing.T) {
	for _, in := range []string{"Example.COM", "xn--bcher-kva.example", "bücher.example:443", "0x7f.1", "a..b", "", "[::1]"} {
		a, aok := RequestHost(in)
		b, bok := hostname.RequestHost(in)
		if a != b || aok != bok {
			t.Errorf("RequestHost(%q) = %q, %v; SDK %q, %v", in, a, aok, b, bok)
		}
	}
	for _, p := range []string{"*.example.com", "*.com", "example.com", "*.0x1"} {
		if IsValidHostnamePattern(p) != hostname.IsValidPattern(p) {
			t.Errorf("IsValidHostnamePattern(%q) differs", p)
		}
	}
	for _, f := range []string{"host.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(src), "\n") > 30 {
			t.Errorf("%s holds more than a delegation", f)
		}
	}
	if _, err := os.Stat("punycode.go"); err == nil {
		t.Error("punycode.go is a copy of the SDK's")
	}
}
