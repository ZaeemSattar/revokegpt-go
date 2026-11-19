package firewall

import (
	"math"
	"strconv"
)

// Request is what the decision needs to know about a request.
type Request struct {
	// Host is the Host header (or URL authority); a port is stripped.
	Host string `json:"host"`
	// Method exactly as received; it must be upper case ([A-Z][A-Z-]*) or the request is refused.
	Method string `json:"method"`
	// RawTarget is the raw request target (r.RequestURI), before any framework rewriting.
	RawTarget string `json:"rawTarget"`
	// FetchMode is "navigate" for Sec-Fetch-Mode: navigate, else "other".
	FetchMode   string `json:"fetchMode"`
	AcceptsHTML bool   `json:"acceptsHtml"`
}

// VerifyOutcome is the result of the siteverify call: Kind is "absent", "pass", "fail" or
// "unreachable". A nil *VerifyOutcome means the call has not been made yet.
type VerifyOutcome struct {
	Kind   string
	Score  float64
	Reason string
}

// VerifySpec is what a needs-verify decision asks the integration to check.
type VerifySpec struct {
	ExpectedAction string  `json:"expectedAction"`
	Threshold      float64 `json:"threshold"`
}

// Decision is the firewall decision for one request. Kind is allow, block, challenge, redirect
// or needs-verify. RuleIndex is nil for the implicit allow, a request refused before the rules,
// and the fail mode.
type Decision struct {
	Kind       string            `json:"kind"`
	RuleIndex  *int              `json:"ruleIndex"`
	Status     int               `json:"status,omitempty"`
	Location   string            `json:"location,omitempty"`
	SetHeaders map[string]string `json:"setHeaders"`
	Verify     *VerifySpec       `json:"verify,omitempty"`
}

// scFloorHundredths maps an sc bucket to the lower bound of its score range in hundredths.
var scFloorHundredths = [4]int{0, 25, 50, 75}

// SessionScoreBucket is the session score bucket sc (0-3) for a siteverify score: quarters of
// the range, 1.0 in bucket 3.
func SessionScoreBucket(score float64) int {
	switch {
	case math.IsNaN(score) || math.IsInf(score, 0) || score <= 0:
		return 0
	case score >= 0.75:
		return 3
	case score >= 0.5:
		return 2
	case score >= 0.25:
		return 1
	}
	return 0
}

func methodMatches(methods []string, method string) bool {
	has := func(m string) bool {
		for _, x := range methods {
			if x == m {
				return true
			}
		}
		return false
	}
	if has(method) {
		return true
	}
	if method == "OPTIONS" {
		return false // OPTIONS only matches a rule that lists it
	}
	if has("*") {
		return true
	}
	return method == "HEAD" && has("GET")
}

func jsRound(x float64) float64 { return math.Floor(x + 0.5) }

func whenHolds(w When, s SessionState) bool {
	if !w.Present {
		return true
	}
	valid := s.Kind == "valid"
	if w.NoSession && valid {
		return false
	}
	if w.SessionLevelBelow != nil {
		lvl := -1
		if valid {
			lvl = s.Lvl
		}
		if !(lvl < *w.SessionLevelBelow) {
			return false
		}
	}
	if w.ScoreBelow != nil {
		// No valid session: the score is unknown, which counts as below any threshold.
		if valid && !(float64(scFloorHundredths[s.Sc]) < jsRound(*w.ScoreBelow*100)) {
			return false
		}
	}
	return true
}

var kindRank = map[string]int{"allow": 1, "needs-verify": 2, "challenge": 3, "redirect": 4, "block": 5}

func stricter(a, b Decision) Decision {
	if kindRank[a.Kind] != kindRank[b.Kind] {
		if kindRank[a.Kind] > kindRank[b.Kind] {
			return a
		}
		return b
	}
	ai, bi := math.Inf(1), math.Inf(1)
	if a.RuleIndex != nil {
		ai = float64(*a.RuleIndex)
	}
	if b.RuleIndex != nil {
		bi = float64(*b.RuleIndex)
	}
	if bi < ai {
		return b
	}
	return a
}

func intPtr(i int) *int { return &i }

func blockDecision(status int, ruleIndex *int, h map[string]string) Decision {
	if h == nil {
		h = map[string]string{}
	}
	return Decision{Kind: "block", RuleIndex: ruleIndex, Status: status, SetHeaders: h}
}

func scoreHeaders(v *VerifyOutcome, s SessionState) map[string]string {
	if v != nil && v.Kind == "pass" {
		return map[string]string{"X-RG-Score": ScoreBucket(v.Score), "X-RG-Verdict": "pass"}
	}
	if s.Kind == "valid" {
		return map[string]string{
			"X-RG-Score":   ScoreBucket(float64(scFloorHundredths[s.Sc]) / 100),
			"X-RG-Verdict": "pass",
		}
	}
	return map[string]string{"X-RG-Score": "0", "X-RG-Verdict": "none"}
}

func evaluate(b *Payload, host, method, path string, r Request, s SessionState, v *VerifyOutcome) Decision {
	headers := map[string]string{}
	wantScore := false
	acc := func() map[string]string {
		h := make(map[string]string, len(headers)+2)
		for k, x := range headers {
			h[k] = x
		}
		if wantScore {
			for k, x := range scoreHeaders(v, s) {
				h[k] = x
			}
		}
		return h
	}
	finishAllow := func(ruleIndex *int, extra map[string]string) Decision {
		h := acc()
		for k, x := range extra {
			h[k] = x
		}
		if ruleIndex != nil {
			h["X-RG-Rule"] = strconv.Itoa(*ruleIndex)
		}
		return Decision{Kind: "allow", RuleIndex: ruleIndex, SetHeaders: h}
	}
	for i := range b.Policies {
		rule := &b.Policies[i]
		if !rule.Enabled || !methodMatches(rule.Methods, method) {
			continue
		}
		hostOK := false
		for _, p := range rule.Hosts {
			if hostnameMatches(host, p) {
				hostOK = true
				break
			}
		}
		if !hostOK || rule.glob == nil || !GlobMatch(rule.glob, path) || !whenHolds(rule.When, s) {
			continue
		}
		var terminal *Action
		for ai := range rule.Actions {
			a := &rule.Actions[ai]
			switch {
			case a.Type == "setHeader":
				headers[a.Name] = a.Value
			case a.Type == "scoreHeader":
				wantScore = true
			case a.terminal():
				terminal = a
			}
		}
		if terminal == nil {
			continue
		}
		idx := intPtr(i)
		switch terminal.Type {
		case "allow":
			return finishAllow(idx, nil)
		case "block":
			return blockDecision(terminal.Status, idx, acc())
		case "redirect":
			// Re-checked here as well as in the editor: a bundle is data, never trusted blindly.
			if !IsSafeRedirectLocation(terminal.Location, b.Hosts) {
				return blockDecision(403, idx, acc())
			}
			return Decision{Kind: "redirect", RuleIndex: idx, Status: terminal.Status, Location: terminal.Location, SetHeaders: acc()}
		case "challengePage":
			if s.Kind == "valid" && s.Lvl >= terminal.MinLevel {
				return finishAllow(idx, nil)
			}
			nav := method == "GET" && r.FetchMode == "navigate" && r.AcceptsHTML
			if nav {
				return Decision{
					Kind: "challenge", RuleIndex: idx, Status: 303,
					Location:   b.ChallengeBase + "/c/" + b.SiteKey + "?h=" + host,
					SetHeaders: acc(),
				}
			}
			h := acc()
			h["X-RG-Action"] = "challenge"
			return Decision{Kind: "challenge", RuleIndex: idx, Status: 403, SetHeaders: h}
		case "requireToken":
			if v == nil {
				return Decision{
					Kind: "needs-verify", RuleIndex: idx, SetHeaders: acc(),
					Verify: &VerifySpec{ExpectedAction: terminal.Action, Threshold: terminal.Threshold},
				}
			}
			switch v.Kind {
			case "unreachable":
				if rule.OnError == "allow" {
					return finishAllow(idx, map[string]string{"X-RG-Verdict": "none"})
				}
				return blockDecision(403, idx, acc())
			case "pass":
				if jsRound(v.Score*1e6) >= jsRound(terminal.Threshold*1e6) {
					wantScore = true
					return finishAllow(idx, nil)
				}
				return blockDecision(403, idx, acc())
			}
			return blockDecision(403, idx, acc()) // absent or fail
		}
	}
	return finishAllow(nil, nil)
}

// Decide is the firewall decision for one request (protocol v1, section 18.4). Pure and total.
//
// Order: (1) a bundle past expiresAt + 6 h applies its fail mode (open: allow, closed: 503);
// (2) a method that is not upper case, or a host that is not a canonical hostname, is a 400;
// (3) a path that is not origin-form or holds a bad escape is a 400; a non-canonical path
// follows onNonCanonical; (4) rules run top to bottom on both forms of the path; the stricter
// decision wins. v is nil until the integration has called siteverify: a matching requireToken
// rule then returns needs-verify, and the integration calls Decide again with the outcome.
func Decide(b *Payload, r Request, s SessionState, v *VerifyOutcome, now int64) Decision {
	if now > b.ExpiresAt+staleGraceSeconds {
		if b.FailMode == "open" {
			return Decision{Kind: "allow", SetHeaders: map[string]string{"X-RG-Verdict": "none"}}
		}
		return blockDecision(503, nil, nil)
	}
	if b.Disabled { // kill switch, on a non-stale bundle only (red team E-2: a stale bundle is not trusted, so its kill switch is not either (v1.md 18.5))
		return Decision{Kind: "allow", SetHeaders: map[string]string{}}
	}
	if !reMethod.MatchString(r.Method) {
		return blockDecision(400, nil, nil)
	}
	host, ok := RequestHost(r.Host)
	if !ok {
		return blockDecision(400, nil, nil)
	}
	n := Normalize(r.RawTarget)
	if !n.OK {
		if n.Reason == "invalid" {
			return blockDecision(400, nil, nil)
		}
		read := r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS"
		if b.OnNonCanonical == "block" || !read {
			return blockDecision(403, nil, nil)
		}
		return Decision{Kind: "allow", SetHeaders: map[string]string{"X-RG-Verdict": "none", "X-RG-Path": "non-canonical"}}
	}
	first := evaluate(b, host, r.Method, n.Path, r, s, v)
	if n.Collapsed == n.Path {
		return first
	}
	return stricter(first, evaluate(b, host, r.Method, n.Collapsed, r, s, v))
}
