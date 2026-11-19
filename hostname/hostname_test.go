package hostname

import "testing"

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
		"ǆ.example", "İ.example", "ｅxample.com", "a\u00ad.com", "ẍ.com", "ﬁ.com",
	} {
		if got, ok := RequestHost(in); ok {
			t.Errorf("RequestHost(%q) = %q, want refusal", in, got)
		}
	}
}

func TestPunycodeRoundTrip(t *testing.T) {
	for _, s := range []string{"bücher", "日本", "łódź", "привет", "ß", "한글", "ひらがな", "αβγ"} {
		enc, ok := encodePunycode([]rune(s))
		if !ok {
			t.Fatalf("encode %q", s)
		}
		dec, ok := decodePunycode(enc)
		if !ok || string(dec) != s {
			t.Errorf("round trip %q -> %q -> %q", s, enc, string(dec))
		}
	}
}
