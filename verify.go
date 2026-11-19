package revokegpt

import (
	"context"
	"net/http"
	"net/url"
	"regexp"

	"github.com/ZaeemSattar/revokegpt-go/hostname"
	"github.com/ZaeemSattar/revokegpt-go/internal/ip"
	"github.com/ZaeemSattar/revokegpt-go/internal/keys"
	"github.com/ZaeemSattar/revokegpt-go/internal/schema"
)

// ExpectedApp is the mobile app a token must have been issued to (protocol v1 section 7).
type ExpectedApp struct {
	// Platform is "android" or "ios".
	Platform string
	// ID is the Android package name (apk_package_name), or the iOS bundle id without the Team ID.
	ID string
}

// VerifyOptions say what a token must carry and what to send along with it.
//
// Go has no null, so an absent option is the zero value or a nil pointer: ExpectedHostname "" , ExpectedApp
// nil, ExpectedAction nil, MinScore nil, RemoteIP "" and SiteKey "" all mean "not given". The protocol's
// "given but null" cases (a null action or threshold) therefore cannot be written in Go, and a pointer to an
// invalid value (a MinScore outside 0 to 1, NaN included) is invalid-expectation.
//
// Give exactly one of ExpectedHostname (canonical: lower case, no trailing dot) and ExpectedApp. MinScore is
// required whenever the token carries a score. A RemoteIP or SiteKey that is empty is not sent.
type VerifyOptions struct {
	ExpectedHostname string
	ExpectedApp      *ExpectedApp
	ExpectedAction   *string
	MinScore         *float64
	RemoteIP         string
	SiteKey          string
}

// VerifyOutcome is the answer of Verify. OK is true only when siteverify verified the token and every
// relying-party check passed; Reason is then "". Result is the parsed siteverify result, or the not-verified
// result when no 200 body was read.
//
// Reason is one of: invalid-expectation, invalid-options, invalid-token-format, network-error, http-error,
// not-verified, app-mismatch, hostname-mismatch, action-mismatch, score-missing, threshold-missing,
// score-invalid, score-below-threshold.
type VerifyOutcome struct {
	OK     bool
	Reason string
	Result SiteverifyResult
}

var (
	androidPackage = regexp.MustCompile(`\A[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\z`)
	iosBundleID    = regexp.MustCompile(`\A[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\z`)
)

func failure(reason string, r SiteverifyResult) VerifyOutcome {
	return VerifyOutcome{Reason: reason, Result: r}
}

func appIDValid(platform, id string) bool {
	switch platform {
	case "android":
		return len(id) <= 255 && androidPackage.MatchString(id)
	case "ios":
		return len(id) <= 155 && iosBundleID.MatchString(id)
	}
	return false
}

func expectationValid(o VerifyOptions) bool {
	if (o.ExpectedHostname == "") == (o.ExpectedApp == nil) {
		return false
	}
	if o.ExpectedApp != nil {
		if !appIDValid(o.ExpectedApp.Platform, o.ExpectedApp.ID) {
			return false
		}
	} else if c, ok := hostname.Canonicalize(o.ExpectedHostname); !ok || c != o.ExpectedHostname {
		return false
	}
	m := o.MinScore
	return m == nil || (*m >= 0 && *m <= 1) // false for NaN
}

// check is the relying-party check of protocol v1 section 7: "" when every check passes, else the reason of the
// first one that failed.
func check(r SiteverifyResult, o VerifyOptions) string {
	if !expectationValid(o) {
		return "invalid-expectation"
	}
	if !r.Verified {
		return "not-verified"
	}
	if app := o.ExpectedApp; app != nil {
		got := r.APKPackageName
		if app.Platform == "ios" {
			got = r.IOSBundleID
		}
		if got == nil || *got != app.ID {
			return "app-mismatch"
		}
	} else if r.Hostname == nil || *r.Hostname != o.ExpectedHostname {
		return "hostname-mismatch"
	}
	if (r.Action == nil) != (o.ExpectedAction == nil) || (r.Action != nil && *r.Action != *o.ExpectedAction) {
		return "action-mismatch"
	}
	switch {
	case r.Score == nil && o.MinScore == nil:
		return ""
	case r.Score == nil:
		return "score-missing"
	case o.MinScore == nil:
		return "threshold-missing"
	case !(*r.Score >= 0 && *r.Score <= 1):
		return "score-invalid"
	case *r.Score < *o.MinScore:
		return "score-below-threshold"
	}
	return ""
}

// Verify checks a response token with siteverify, then applies the relying-party checks. It never returns an
// error and never panics: every failure is an outcome with a Reason, and a bad option is reported before any
// request is made (a token is single use, so none is spent on a call that cannot pass). Gate on OK alone.
//
// The deadline is the client's timeout, applied to the whole exchange together with ctx: whichever ends first.
// A cancelled or expired context gives "network-error". Nothing is retried.
func (c *Client) Verify(ctx context.Context, tok string, o VerifyOptions) (out VerifyOutcome) {
	defer func() {
		if recover() != nil {
			out = failure("not-verified", notVerified())
		}
	}()
	if c == nil || c.c == nil {
		return failure("not-verified", notVerified())
	}
	if !expectationValid(o) {
		return failure("invalid-expectation", notVerified())
	}
	form := url.Values{}
	// An empty remoteip or sitekey is not sent (siteverify refuses an empty remoteip as bad-request).
	if o.RemoteIP != "" {
		if _, ok := ip.Canonical(o.RemoteIP); !ok {
			return failure("invalid-options", notVerified())
		}
		form.Set("remoteip", o.RemoteIP)
	}
	if o.SiteKey != "" {
		if !keys.IsSiteKey(o.SiteKey) {
			return failure("invalid-options", notVerified())
		}
		form.Set("sitekey", o.SiteKey)
	}
	if !schema.ResponseToken(tok) {
		return failure("invalid-token-format", notVerified())
	}
	form.Set("secret", string(c.c.secret))
	form.Set("response", tok)
	raw, err := c.c.do(ctx, request{
		url: c.c.endpoint, contentType: "application/x-www-form-urlencoded", body: []byte(form.Encode()), limit: maxResponseBytes,
	})
	if err != nil {
		return failure("network-error", notVerified())
	}
	// Any status but 200 (a redirect included) is "not verified" (section 7); so is a body over the cap.
	if raw.Status != http.StatusOK || raw.TooLarge || raw.Body == nil {
		return failure("http-error", notVerified())
	}
	res := parseSiteverify(raw.Body)
	if reason := check(res, o); reason != "" {
		return failure(reason, res)
	}
	return VerifyOutcome{OK: true, Result: res}
}
