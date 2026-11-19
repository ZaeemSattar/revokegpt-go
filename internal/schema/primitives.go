// Package schema judges request bodies and response bodies of the RevokeGPT API (protocol v1 sections 14 to 17
// and 20) the way the zod schemas of the reference do. Each function takes the parsed JSON form of a value
// (jsonx.Parse output, or a map built by the SDK) and reports whether it fits. It does no I/O and never puts a
// value in a message: it returns only a bool.
//
// Rules shared by every schema here:
//   - A strict object accepts only its named keys. A JSON null where a value is optional is invalid (it is
//     not "absent").
//   - A string length is counted in UTF-16 code units, as JavaScript counts it, so every SDK agrees on a string
//     near a limit. A string that is not valid UTF-8 is never valid.
//   - A number is a finite JSON number. A json.Number that does not fit a float64 (1e999) is not finite.
//   - Every character class is ASCII only.
package schema

import (
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"unicode/utf8"
)

// Object is a parsed JSON object.
type Object = map[string]any

// u16 is the length JavaScript gives a string: UTF-16 code units.
func u16(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// str reports whether v is a valid UTF-8 string with a UTF-16 length from lo to hi (hi < 0: no upper bound).
func str(v any, lo, hi int) bool {
	s, ok := v.(string)
	if !ok || !utf8.ValidString(s) {
		return false
	}
	n := u16(s)
	return n >= lo && (hi < 0 || n <= hi)
}

func matches(rx *regexp.Regexp, v any) bool {
	s, ok := v.(string)
	return ok && rx.MatchString(s)
}

// number is a finite JSON number as a float64.
func number(v any) (float64, bool) {
	var f float64
	switch n := v.(type) {
	case json.Number:
		var err error
		if f, err = strconv.ParseFloat(n.String(), 64); err != nil {
			return 0, false
		}
	case float64:
		f = n
	case float32:
		f = float64(n)
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	default:
		return 0, false
	}
	return f, !math.IsNaN(f) && !math.IsInf(f, 0)
}

func isInt(v any) bool {
	f, ok := number(v)
	return ok && f == math.Trunc(f)
}

func money(v any) bool {
	f, ok := number(v)
	return ok && f >= 0 && f <= 1e12
}

func risk(v any) bool {
	f, ok := number(v)
	return ok && f >= 0 && f <= 1
}

func list(v any, lo, hi int) ([]any, bool) {
	l, ok := v.([]any)
	if !ok || len(l) < lo || (hi >= 0 && len(l) > hi) {
		return nil, false
	}
	return l, true
}

func all(l []any, ok func(any) bool) bool {
	for _, x := range l {
		if !ok(x) {
			return false
		}
	}
	return true
}

// keysOK is a strict object: a map with only the named keys.
func keysOK(v any, allowed ...string) (Object, bool) {
	m, ok := v.(Object)
	if !ok {
		return nil, false
	}
	for k := range m {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return m, true
}

// has is an optional field: absent, or present and valid.
func has(m Object, key string, ok func(any) bool) bool {
	v, present := m[key]
	return !present || ok(v)
}

func oneOf(v any, set ...string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}

var (
	hashedAccountID = regexp.MustCompile(`\A[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=\z`)
	base64url32     = regexp.MustCompile(`\A[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]\z`)
	base64url8      = regexp.MustCompile(`\A[A-Za-z0-9_-]{10}[AEIMQUYcgkosw048]\z`)
	cdata           = regexp.MustCompile(`\A[A-Za-z0-9_-]{0,255}\z`)
	e164            = regexp.MustCompile(`\A\+[1-9][0-9]{6,14}\z`)
	languageCode    = regexp.MustCompile(`\A[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}\z`)
	aid             = regexp.MustCompile(`\A(?:assessments/)?[A-Za-z0-9_-]{42}\z`)
	assessmentName  = regexp.MustCompile(`\Aassessments/[A-Za-z0-9_-]{42}\z`)
	openReason      = regexp.MustCompile(`\A[A-Z_]{1,64}\z`)
	paymentMethod   = regexp.MustCompile(`\A(?:credit-card|debit-card|gift-card|processor-[a-z0-9-]{1,32}|custom-[a-z0-9-]{1,32})\z`)
	cardBin         = regexp.MustCompile(`\A(?:[0-9]{6}|[0-9]{8})\z`)
	lastFour        = regexp.MustCompile(`\A[0-9]{4}\z`)
	currency        = regexp.MustCompile(`\A[A-Z]{3}\z`)
	region          = regexp.MustCompile(`\A[A-Z]{2}\z`)
	creationMs      = regexp.MustCompile(`\A[0-9]{1,13}\z`)
	gatewayName     = regexp.MustCompile(`\A[a-z0-9_-]{1,32}\z`)

	// An RFC 3339 date-time with an offset, spelled with [0-9] so no other script's digits match (a leap day only
	// in a leap year). The same pattern as DATE_TIME in packages/protocol/src/patterns.ts.
	dateTime = regexp.MustCompile(`\A(?:(?:[0-9][0-9][2468][048]|[0-9][0-9][13579][26]|[0-9][0-9]0[48]|[02468][048]00|[13579][26]00)-02-29` +
		`|[0-9]{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])|(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)` +
		`|(?:02)-(?:0[1-9]|1[0-9]|2[0-8])))` +
		`T(?:(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?(?:Z|(?:[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])))\z`)
)

// DateTime reports whether s is an RFC 3339 date-time with an offset.
func DateTime(s string) bool { return dateTime.MatchString(s) }

func dateTimeValue(v any) bool {
	s, ok := v.(string)
	return ok && dateTime.MatchString(s)
}

// ResponseToken reports whether s is 1 to 2048 ASCII letters, digits, "_" or "-". (RE2 repeats at most 1000
// times, so no regexp.)
func ResponseToken(s string) bool {
	if len(s) < 1 || len(s) > 2048 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
