package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"strings"
)

// Key is a public key entry: a pinned bundle key, or a session key in a bundle's tokenKeys.
type Key struct {
	Kid      string `json:"kid"`
	Alg      string `json:"alg"`
	Pub      string `json:"pub"`
	NotAfter int64  `json:"notAfter"`
}

// Action is one rule action. Type is one of allow, block, requireToken, challengePage, redirect
// (terminal) and scoreHeader, setHeader (not terminal).
type Action struct {
	Type      string
	Status    int     // block, redirect
	Action    string  // requireToken
	Threshold float64 // requireToken
	MinLevel  int     // challengePage
	Location  string  // redirect
	Name      string  // setHeader
	Value     string  // setHeader
}

func (a Action) terminal() bool {
	switch a.Type {
	case "allow", "block", "requireToken", "challengePage", "redirect":
		return true
	}
	return false
}

// When holds the optional predicates of a rule.
type When struct {
	Present           bool
	ScoreBelow        *float64
	SessionLevelBelow *int
	NoSession         bool
}

// Rule is one validated firewall rule. Its glob is compiled once, at parse time.
type Rule struct {
	ID      string
	Name    string
	Enabled bool
	Hosts   []string
	Path    string
	Methods []string
	When    When
	Actions []Action
	OnError string

	glob *Glob
}

// SessionConfig is the bundle's session block.
type SessionConfig struct {
	TTL          int64
	Max          int64
	ClearanceTTL int64
}

// Payload is a validated bundle payload (protocol v1, section 18.5).
type Payload struct {
	V               int
	SiteID          string
	SiteKey         string
	ChallengeBase   string
	Version         int64
	IssuedAt        int64
	NotBefore       int64
	ExpiresAt       int64
	FailMode        string
	OnNonCanonical  string
	MinIat          int64
	SigHeader       bool
	Disabled        bool // kill switch: pass every request through untouched
	RevokedJti      []string
	Session         SessionConfig
	Hosts           []string
	TokenKeys       []Key
	Policies        []Rule
	usesCookiesFlag bool
}

var (
	reBase62ID  = regexp.MustCompile(`^[0-9A-Za-z]{8}$`)
	reKid       = regexp.MustCompile(`^[0-9a-f]{16}$`)
	reJti       = regexp.MustCompile(`^[A-Za-z0-9_-]{16,32}$`)
	reMethod    = regexp.MustCompile(`^[A-Z][A-Z-]{0,31}$`)
	reHeaderNm  = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	reSiteID    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reSiteKey   = regexp.MustCompile(`^rgpk_[0-9A-Za-z]{20}$`)
	reAction    = regexp.MustCompile(`^[A-Za-z0-9/_]{1,100}$`)
	reKeyPub    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	reChallenge = regexp.MustCompile(`^https://([a-z0-9.-]+)(?::[0-9]{1,5})?$`)
	reSetValue  = regexp.MustCompile(`^[\x20-\x7e]*$`)
)

// nameForbidden: C0/C1 controls and bidirectional controls in a rule name.
func nameForbidden(s string) bool {
	for _, r := range s {
		switch {
		case r <= 0x1f, r >= 0x7f && r <= 0x9f:
			return true
		case r == 0x200e, r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			return true
		}
	}
	return false
}

var setHeaderDeny = map[string]bool{
	"host": true, "forwarded": true, "content-length": true, "transfer-encoding": true,
	"set-cookie": true, "cookie": true, "authorization": true, "connection": true,
	"keep-alive": true, "proxy-authenticate": true, "proxy-authorization": true,
	"proxy-connection": true, "te": true, "trailer": true, "trailers": true, "upgrade": true,
}

// IsSettableHeaderName reports whether a setHeader action may set this header.
func IsSettableHeaderName(name string) bool {
	if name == "" || len(name) > maxSetHeaderName || !reHeaderNm.MatchString(name) {
		return false
	}
	if setHeaderDeny[name] {
		return false
	}
	return !(strings.HasPrefix(name, "x-rg-") || strings.HasPrefix(name, "x-forwarded-") || name == "x-rg")
}

// IsSettableHeaderValue: printable ASCII, at most 256 characters.
func IsSettableHeaderValue(v string) bool {
	return len(v) <= maxSetHeaderValue && reSetValue.MatchString(v)
}

// IsSafeRedirectLocation: a path ("/x", not "//", no backslash, no control) or an https URL on a
// site host.
func IsSafeRedirectLocation(loc string, siteHosts []string) bool {
	if loc == "" || utf16Len(loc) > 2048 {
		return false
	}
	for _, r := range loc {
		if r <= 0x20 || r >= 0x7f || r == '\\' {
			return false
		}
	}
	if loc[0] == '/' {
		return !strings.HasPrefix(loc, "//")
	}
	if !strings.HasPrefix(loc, "https://") {
		return false
	}
	rest := loc[len("https://"):]
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		if strings.IndexByte("/?#:@", rest[i]) >= 0 {
			end = i
			break
		}
	}
	hostPart := rest[:end]
	tail := rest[end:]
	if hostPart == "" {
		return false
	}
	// Optional ":port" then an optional path, query or fragment; userinfo ("@") is refused.
	if strings.HasPrefix(tail, ":") {
		i := 1
		for i < len(tail) && tail[i] >= '0' && tail[i] <= '9' {
			i++
		}
		if i == 1 || i > 6 {
			return false
		}
		tail = tail[i:]
	}
	if tail != "" && strings.IndexByte("/?#", tail[0]) < 0 {
		return false
	}
	host, ok := CanonicalizeHostname(hostPart)
	if !ok {
		return false
	}
	for _, p := range siteHosts {
		if IsValidHostnamePattern(p) && patternCovers(p, host) {
			return true
		}
	}
	return false
}

// patternCovers: site pattern `site` matches every host that pattern-or-host `rule` matches.
func patternCovers(site, rule string) bool {
	if site == rule {
		return true
	}
	if !strings.HasPrefix(site, "*.") {
		return false
	}
	base := site[2:]
	target := strings.TrimPrefix(rule, "*.")
	return target != base && strings.HasSuffix(target, "."+base)
}

// ---- strict JSON reading -------------------------------------------------------------------

var errSchema = errors.New("schema")

type obj = map[string]any

func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

// strictObject returns the object, or an error if it has a key outside allowed or lacks a
// required one.
func strictObject(v any, allowed []string, required []string) (obj, error) {
	m, ok := v.(obj)
	if !ok {
		return nil, errSchema
	}
	for k := range m {
		found := false
		for _, a := range allowed {
			if a == k {
				found = true
				break
			}
		}
		if !found {
			return nil, errSchema
		}
	}
	for _, r := range required {
		if _, ok := m[r]; !ok {
			return nil, errSchema
		}
	}
	return m, nil
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// asInt reads a JSON number as an integer (1.0 and 1e2 count, as in JavaScript), within min..max.
func asInt(v any, min, max int64) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) {
		return 0, false
	}
	if f < float64(min) || f > float64(max) {
		return 0, false
	}
	return int64(f), true
}

func asFloat(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

func asThreshold(v any) (float64, bool) {
	f, ok := asFloat(v)
	if !ok || f < 0.1 || f > 1 || math.Round(f*10)/10 != f {
		return 0, false
	}
	return f, true
}

func asStringArray(v any, min, max int) ([]string, bool) {
	a, ok := v.([]any)
	if !ok || len(a) < min || len(a) > max {
		return nil, false
	}
	out := make([]string, len(a))
	for i, x := range a {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func parseKey(v any) (Key, bool) {
	m, err := strictObject(v, []string{"kid", "alg", "pub", "notAfter"}, []string{"kid", "alg", "pub", "notAfter"})
	if err != nil {
		return Key{}, false
	}
	kid, ok1 := asString(m["kid"])
	alg, ok2 := asString(m["alg"])
	pub, ok3 := asString(m["pub"])
	na, ok4 := asInt(m["notAfter"], 0, maxSafeInteger)
	if !ok1 || !ok2 || !ok3 || !ok4 || !reKid.MatchString(kid) || alg != "Ed25519" || !reKeyPub.MatchString(pub) {
		return Key{}, false
	}
	return Key{Kid: kid, Alg: alg, Pub: pub, NotAfter: na}, true
}

func parseAction(v any) (Action, bool) {
	m, ok := v.(obj)
	if !ok {
		return Action{}, false
	}
	t, ok := asString(m["type"])
	if !ok {
		return Action{}, false
	}
	a := Action{Type: t}
	switch t {
	case "allow", "scoreHeader":
		_, err := strictObject(m, []string{"type"}, []string{"type"})
		return a, err == nil
	case "block":
		if _, err := strictObject(m, []string{"type", "status"}, []string{"type", "status"}); err != nil {
			return a, false
		}
		s, ok := asInt(m["status"], 0, 1000)
		if !ok || (s != 403 && s != 404 && s != 429) {
			return a, false
		}
		a.Status = int(s)
		return a, true
	case "requireToken":
		if _, err := strictObject(m, []string{"type", "action", "threshold"}, []string{"type", "action", "threshold"}); err != nil {
			return a, false
		}
		act, ok1 := asString(m["action"])
		th, ok2 := asThreshold(m["threshold"])
		if !ok1 || !ok2 || !reAction.MatchString(act) {
			return a, false
		}
		a.Action, a.Threshold = act, th
		return a, true
	case "challengePage":
		if _, err := strictObject(m, []string{"type", "minLevel"}, []string{"type", "minLevel"}); err != nil {
			return a, false
		}
		l, ok := asInt(m["minLevel"], 0, 1000)
		if !ok || (l != 1 && l != 2) {
			return a, false
		}
		a.MinLevel = int(l)
		return a, true
	case "redirect":
		if _, err := strictObject(m, []string{"type", "location", "status"}, []string{"type", "location", "status"}); err != nil {
			return a, false
		}
		loc, ok1 := asString(m["location"])
		s, ok2 := asInt(m["status"], 0, 1000)
		if !ok1 || !ok2 || loc == "" || utf16Len(loc) > 2048 || (s != 302 && s != 307 && s != 308) {
			return a, false
		}
		a.Location, a.Status = loc, int(s)
		return a, true
	case "setHeader":
		if _, err := strictObject(m, []string{"type", "name", "value"}, []string{"type", "name", "value"}); err != nil {
			return a, false
		}
		name, ok1 := asString(m["name"])
		val, ok2 := asString(m["value"])
		if !ok1 || !ok2 || !IsSettableHeaderName(name) || !IsSettableHeaderValue(val) {
			return a, false
		}
		a.Name, a.Value = name, val
		return a, true
	}
	return a, false
}

func parseRule(v any) (Rule, bool) {
	m, err := strictObject(v, []string{"id", "name", "enabled", "match", "when", "actions", "onError"},
		[]string{"id", "name", "enabled", "match", "actions", "onError"})
	if err != nil {
		return Rule{}, false
	}
	var r Rule
	var ok bool
	if r.ID, ok = asString(m["id"]); !ok || !reBase62ID.MatchString(r.ID) {
		return r, false
	}
	if r.Name, ok = asString(m["name"]); !ok {
		return r, false
	}
	if n := utf16Len(r.Name); n < 1 || n > maxRuleName || nameForbidden(r.Name) {
		return r, false
	}
	if r.Enabled, ok = m["enabled"].(bool); !ok {
		return r, false
	}
	match, err := strictObject(m["match"], []string{"hosts", "path", "methods"}, []string{"hosts", "path", "methods"})
	if err != nil {
		return r, false
	}
	if r.Hosts, ok = asStringArray(match["hosts"], 1, maxHostsPerRule); !ok {
		return r, false
	}
	for _, h := range r.Hosts {
		if !IsValidHostnamePattern(h) {
			return r, false
		}
	}
	if r.Path, ok = asString(match["path"]); !ok {
		return r, false
	}
	if r.glob = CompileGlob(r.Path); r.glob == nil {
		return r, false
	}
	if r.Methods, ok = asStringArray(match["methods"], 1, maxMethodsPerRule); !ok {
		return r, false
	}
	seen := map[string]bool{}
	for _, me := range r.Methods {
		if me != "*" && !reMethod.MatchString(me) {
			return r, false
		}
		if seen[me] {
			return r, false
		}
		seen[me] = true
	}
	if seen["*"] && len(r.Methods) != 1 {
		return r, false
	}
	if w, has := m["when"]; has {
		wm, err := strictObject(w, []string{"scoreBelow", "sessionLevelBelow", "noSession"}, nil)
		if err != nil {
			return r, false
		}
		r.When.Present = true
		if x, has := wm["scoreBelow"]; has {
			f, ok := asThreshold(x)
			if !ok {
				return r, false
			}
			r.When.ScoreBelow = &f
		}
		if x, has := wm["sessionLevelBelow"]; has {
			l, ok := asInt(x, 0, 1000)
			if !ok || l > 2 {
				return r, false
			}
			li := int(l)
			r.When.SessionLevelBelow = &li
		}
		if x, has := wm["noSession"]; has {
			if b, ok := x.(bool); !ok || !b {
				return r, false
			}
			r.When.NoSession = true
		}
	}
	acts, ok := m["actions"].([]any)
	if !ok || len(acts) < 1 || len(acts) > maxActionsPerRule {
		return r, false
	}
	terminals := 0
	for _, x := range acts {
		a, ok := parseAction(x)
		if !ok {
			return r, false
		}
		if a.terminal() {
			terminals++
		}
		r.Actions = append(r.Actions, a)
	}
	if terminals > 1 {
		return r, false
	}
	if r.OnError, ok = asString(m["onError"]); !ok || (r.OnError != "allow" && r.OnError != "block") {
		return r, false
	}
	return r, true
}

// ParsePayload reads and validates a bundle payload (strict: unknown fields are refused) as
// PolicyBundlePayloadSchema does. The error is only ever errSchema-shaped; callers report
// "schema".
func ParsePayload(raw []byte) (*Payload, error) {
	v, err := decodeJSON(raw)
	if err != nil {
		return nil, errSchema
	}
	keys := []string{"v", "siteId", "siteKey", "challengeBase", "version", "issuedAt", "notBefore", "expiresAt",
		"failMode", "onNonCanonical", "minIat", "sigHeader", "disabled", "revokedJti", "session", "hosts", "tokenKeys", "policies"}
	required := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != "onNonCanonical" && k != "sigHeader" && k != "disabled" {
			required = append(required, k)
		}
	}
	m, err := strictObject(v, keys, required)
	if err != nil {
		return nil, errSchema
	}
	p := &Payload{}
	var ok bool
	if x, ok := asInt(m["v"], 1, 1); !ok || x != 1 {
		return nil, errSchema
	}
	p.V = 1
	if p.SiteID, ok = asString(m["siteId"]); !ok || !reSiteID.MatchString(p.SiteID) {
		return nil, errSchema
	}
	if p.SiteKey, ok = asString(m["siteKey"]); !ok || !reSiteKey.MatchString(p.SiteKey) {
		return nil, errSchema
	}
	if p.ChallengeBase, ok = asString(m["challengeBase"]); !ok || utf16Len(p.ChallengeBase) > 300 {
		return nil, errSchema
	}
	cm := reChallenge.FindStringSubmatch(p.ChallengeBase)
	if cm == nil {
		return nil, errSchema
	}
	if c, ok := CanonicalizeHostname(cm[1]); !ok || c != cm[1] {
		return nil, errSchema
	}
	if p.Version, ok = asInt(m["version"], 1, maxSafeInteger); !ok {
		return nil, errSchema
	}
	if p.IssuedAt, ok = asInt(m["issuedAt"], 0, maxSafeInteger); !ok {
		return nil, errSchema
	}
	if p.NotBefore, ok = asInt(m["notBefore"], 0, maxSafeInteger); !ok {
		return nil, errSchema
	}
	if p.ExpiresAt, ok = asInt(m["expiresAt"], 0, maxSafeInteger); !ok {
		return nil, errSchema
	}
	if p.FailMode, ok = asString(m["failMode"]); !ok || (p.FailMode != "open" && p.FailMode != "closed") {
		return nil, errSchema
	}
	p.OnNonCanonical = "block-writes"
	if x, has := m["onNonCanonical"]; has {
		s, ok := asString(x)
		if !ok || (s != "block-writes" && s != "block") {
			return nil, errSchema
		}
		p.OnNonCanonical = s
	}
	if p.MinIat, ok = asInt(m["minIat"], 0, maxSafeInteger); !ok {
		return nil, errSchema
	}
	// sigHeader is optional and must be a boolean; true asks the integration to sign X-RG-Sig.
	if x, has := m["sigHeader"]; has {
		bv, isBool := x.(bool)
		if !isBool {
			return nil, errSchema
		}
		p.SigHeader = bv
	}
	// disabled is optional and must be a boolean; true is the kill switch (absent = false).
	if x, has := m["disabled"]; has {
		bv, isBool := x.(bool)
		if !isBool {
			return nil, errSchema
		}
		p.Disabled = bv
	}
	if p.RevokedJti, ok = asStringArray(m["revokedJti"], 0, maxRevokedJti); !ok {
		return nil, errSchema
	}
	for _, j := range p.RevokedJti {
		if !reJti.MatchString(j) {
			return nil, errSchema
		}
	}
	sm, err := strictObject(m["session"], []string{"ttl", "max", "clearanceTtl"}, []string{"ttl", "max", "clearanceTtl"})
	if err != nil {
		return nil, errSchema
	}
	var ok1, ok2, ok3 bool
	p.Session.TTL, ok1 = asInt(sm["ttl"], 300, 86400)
	p.Session.Max, ok2 = asInt(sm["max"], 300, 86400)
	p.Session.ClearanceTTL, ok3 = asInt(sm["clearanceTtl"], 300, 86400)
	if !ok1 || !ok2 || !ok3 || p.Session.TTL > p.Session.Max {
		return nil, errSchema
	}
	if p.Hosts, ok = asStringArray(m["hosts"], 1, maxSiteHosts); !ok {
		return nil, errSchema
	}
	for _, h := range p.Hosts {
		if !IsValidHostnamePattern(h) {
			return nil, errSchema
		}
	}
	tk, ok := m["tokenKeys"].([]any)
	if !ok || len(tk) < 1 || len(tk) > 4 {
		return nil, errSchema
	}
	for _, x := range tk {
		k, ok := parseKey(x)
		if !ok {
			return nil, errSchema
		}
		p.TokenKeys = append(p.TokenKeys, k)
	}
	pol, ok := m["policies"].([]any)
	if !ok || len(pol) > maxPolicies {
		return nil, errSchema
	}
	ids := map[string]bool{}
	for _, x := range pol {
		r, ok := parseRule(x)
		if !ok || ids[r.ID] {
			return nil, errSchema
		}
		ids[r.ID] = true
		p.Policies = append(p.Policies, r)
		if r.When.Present {
			p.usesCookiesFlag = true
		}
		for _, a := range r.Actions {
			if a.Type == "challengePage" {
				p.usesCookiesFlag = true
			}
		}
	}
	if !(p.ExpiresAt > p.NotBefore && p.ExpiresAt-p.NotBefore <= 86400) {
		return nil, errSchema
	}
	return p, nil
}

// UsesCookies reports whether any rule's outcome can depend on a session or clearance cookie
// (a `when` predicate or a challengePage action). Such responses carry `Vary: Cookie`.
func (p *Payload) UsesCookies() bool { return p.usesCookiesFlag }
