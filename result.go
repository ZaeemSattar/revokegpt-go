package revokegpt

import (
	"encoding/json"
	"strconv"

	"github.com/ZaeemSattar/revokegpt-go/internal/jsonx"
	"github.com/ZaeemSattar/revokegpt-go/internal/schema"
)

// SiteverifyResult is what a relying party reads from a siteverify response. Gate on Verified alone.
//
// An optional field is a pointer: nil is "absent", the same as JSON null is never accepted for a known field
// (a response with a null or mistyped known field is the not-verified result).
type SiteverifyResult struct {
	// Verified is true only for a well-formed body whose "success" is exactly the JSON value true.
	Verified bool
	Score    *float64
	Action   *string
	Hostname *string
	// ErrorCodes and Reasons are never nil.
	ErrorCodes []string
	Reasons    []string
	// APKPackageName is the Android package name (apk_package_name).
	APKPackageName *string
	// IOSBundleID is the iOS bundle id (ios_bundle_id).
	IOSBundleID *string
}

func notVerified() SiteverifyResult {
	return SiteverifyResult{ErrorCodes: []string{}, Reasons: []string{}}
}

func optString(m map[string]any, key string) (*string, bool) {
	v, present := m[key]
	if !present {
		return nil, true
	}
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	return &s, true
}

func stringList(m map[string]any, key string) ([]string, bool) {
	v, present := m[key]
	if !present {
		return []string{}, true
	}
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(list))
	for i, x := range list {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// parseSiteverify returns the not-verified result unless body is a JSON object whose known fields all have
// their documented type and range and whose "success" is exactly true. It never panics.
func parseSiteverify(body []byte) (res SiteverifyResult) {
	defer func() {
		if recover() != nil {
			res = notVerified()
		}
	}()
	v, err := jsonx.Parse(body)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return notVerified()
	}
	success, ok := m["success"].(bool)
	if !ok {
		return notVerified()
	}
	out := notVerified()
	out.Verified = success
	for _, f := range []struct {
		key string
		dst **string
	}{{"hostname", &out.Hostname}, {"action", &out.Action}, {"apk_package_name", &out.APKPackageName}, {"ios_bundle_id", &out.IOSBundleID}} {
		if *f.dst, ok = optString(m, f.key); !ok {
			return notVerified()
		}
	}
	// cdata and mode are known string fields the result does not carry; they are still validated.
	for _, key := range []string{"cdata", "mode"} {
		if _, ok = optString(m, key); !ok {
			return notVerified()
		}
	}
	if out.ErrorCodes, ok = stringList(m, "error-codes"); !ok {
		return notVerified()
	}
	if out.Reasons, ok = stringList(m, "reasons"); !ok {
		return notVerified()
	}
	if raw, present := m["score"]; present {
		n, isNum := raw.(json.Number)
		if !isNum {
			return notVerified()
		}
		// A number outside float64 (1e999) is an error from ParseFloat: it is not a score in [0, 1].
		f, err := strconv.ParseFloat(n.String(), 64)
		if err != nil || !(f >= 0 && f <= 1) {
			return notVerified()
		}
		out.Score = &f
	}
	if raw, present := m["challenge_ts"]; present {
		ts, isStr := raw.(string)
		if !isStr || !schema.DateTime(ts) {
			return notVerified()
		}
	}
	return out
}
