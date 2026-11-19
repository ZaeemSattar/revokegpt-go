package firewall

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// StripRgHeaders returns, in order and with duplicates, the names (from an incoming header list)
// to delete on ingress: every name that, case-insensitively and with "_" read as "-", starts
// with "x-rg-". That covers X_RG_Score (which CGI, WSGI and PHP map to the same variable as
// X-RG-Score) and the bare prefix. "x-rgx" is kept.
func StripRgHeaders(names []string) []string {
	var out []string
	for _, n := range names {
		if isRgHeader(n) {
			out = append(out, n)
		}
	}
	return out
}

func isRgHeader(name string) bool {
	return strings.HasPrefix(strings.ReplaceAll(strings.ToLower(name), "_", "-"), "x-rg-")
}

// ScoreBucket is the X-RG-Score value: the score floored to a multiple of 10 on 0-100 as a
// string; NaN, infinities and negatives give "0".
func ScoreBucket(score float64) string {
	if math.IsNaN(score) || math.IsInf(score, 0) || score <= 0 {
		return "0"
	}
	if score >= 1 {
		return "100"
	}
	// JavaScript Math.round rounds half up; the argument is non-negative here.
	return strconv.Itoa(int(math.Floor(math.Floor(score*1e6+0.5)/1e5)) * 10)
}

var (
	reEncodedControl = regexp.MustCompile(`%(?:[01][0-9A-Fa-f]|7[Ff])`)
	reEncodedSep     = regexp.MustCompile(`%(?:2[Ff]|5[Cc])`)
	reDotSegment     = regexp.MustCompile(`(?:^|/)(?:\.|%2[Ee]){1,2}(?:/|$)`)
)

// IsSafeReturnPath reports whether p is safe to use as a return path (__Host-rg_r, Location
// after /__rg/return): a relative path that starts with a single "/", has no backslash, space,
// control or non-ASCII character, no "//" and no dot segment (encoded or not) in its path
// part, no encoded "/", "\" in the path part (and no encoded control anywhere), is at most 2048
// characters, and does not point into /__rg/. Anything else lands on "/".
func IsSafeReturnPath(p string) bool {
	if p == "" || utf16Len(p) > maxReturnPathLength {
		return false
	}
	if p[0] != '/' || (len(p) > 1 && (p[1] == '/' || p[1] == '\\')) {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c <= 0x20 || c >= 0x7f || c == '\\' {
			return false
		}
	}
	if reEncodedControl.MatchString(p) {
		return false
	}
	path := p
	if q := strings.IndexAny(p, "?#"); q >= 0 {
		path = p[:q]
	}
	if reEncodedSep.MatchString(path) || strings.Contains(path, "//") {
		return false
	}
	if reDotSegment.MatchString(path) {
		return false
	}
	return !(path == "/__rg" || strings.HasPrefix(path, "/__rg/"))
}
