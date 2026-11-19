// Package firewall is the RevokeGPT firewall for Go net/http. It evaluates the site's signed
// policy bundle in front of an http.Handler: block, redirect, challenge and token-gated routes,
// with the same decisions as the reference implementation (protocol v1, section 18).
//
// Mount Middleware OUTSIDE any http.ServeMux: a ServeMux cleans the path and redirects "//"
// before a handler runs, which would hide the raw request target from the firewall.
package firewall

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Version is the integration version sent as X-RG-Integration: go-net-http/<Version>.
const Version = "0.1.1"

const defaultAPIBase = "https://api.revokegpt.com"

// Config configures a Firewall.
type Config struct {
	// SiteKey (rgpk_...) names the bundle to fetch. Required.
	SiteKey string
	// SecretKey (rgsk_...) is used for siteverify and for a private bundle. Without it a
	// requireToken rule can never pass (the request gets the rule's onError).
	SecretKey string
	// APIBase is the API origin. Default https://api.revokegpt.com. It must be https
	// (http only for localhost, 127.0.0.1 and [::1]) and have no path, query or userinfo.
	APIBase string
	// SiteID, when set, is the site UUID every bundle must carry, and the bundle's siteKey
	// must equal SiteKey. When empty, the site id of the first verified bundle is pinned.
	SiteID string
	// PinnedKeys are the bundle verification keys. Default PinnedPolicyKeys (placeholders that
	// fail closed until the owner supplies the real public keys).
	PinnedKeys []Key
	// InitialFailMode applies while no bundle has ever been verified: "open" (default;
	// requests pass to the origin with X-RG-Verdict: none) or "closed" (503). An authentic 404
	// from the policies endpoint (no published policies) always passes. Once a bundle is
	// cached, its own failMode applies after expiresAt + 6 h.
	InitialFailMode string
	// RefreshInterval overrides the bundle refresh period (default 60 s plus 0 to 20 s of
	// jitter; an override has no jitter). For tests and conformance runs.
	RefreshInterval time.Duration
	// HTTPClient is used for the API. Redirects are never followed.
	HTTPClient *http.Client
	// Now is the clock. Default time.Now.
	Now func() time.Time
	// Store remembers the highest accepted bundle version per site. Default in memory.
	Store VersionStore
	// SigSecret, when set (a string of at least 16 characters), signs X-RG-Sig on requests
	// passed to the origin, if the bundle's settings turn sigHeader on. Without it the header is
	// never sent (a one-time config warning is logged when the bundle asks for it).
	SigSecret string
	// Logger receives one line per decision (decision id, rule index, action) and nothing
	// else: never a token, cookie, key or query string. Default slog.Default().
	Logger *slog.Logger
}

// Firewall is a configured firewall. Safe for concurrent use.
type Firewall struct {
	siteKey          string
	secret           string
	sigSecret        string
	sigWarned        atomic.Bool
	apiBase          string
	integration      string
	pinned           []Key
	failOpen         bool
	httpc            *http.Client
	now              func() time.Time
	store            VersionStore
	log              *slog.Logger
	breaker          *breaker
	flight           flightGroup
	siteIDPinned     bool
	canonicalSiteKey bool

	refreshBase  time.Duration
	refreshExtra time.Duration

	mu          sync.RWMutex
	siteID      string
	payload     *Payload
	etag        string
	nextRefresh time.Time
	lastFail    time.Time
	notFound    bool
	authOnce    sync.Once
}

var (
	reCfgSiteKey = regexp.MustCompile(`^rgpk_[A-Za-z0-9_]+$`)
	reCfgSecret  = regexp.MustCompile(`^rgsk_[A-Za-z0-9_-]+$`)
)

// New validates cfg and returns a Firewall. It makes no network call.
func New(cfg Config) (*Firewall, error) {
	if !reCfgSiteKey.MatchString(cfg.SiteKey) || len(cfg.SiteKey) > 128 {
		return nil, errors.New("firewall: invalid SiteKey")
	}
	if cfg.SecretKey != "" && (!reCfgSecret.MatchString(cfg.SecretKey) || len(cfg.SecretKey) > 256) {
		return nil, errors.New("firewall: invalid SecretKey")
	}
	if cfg.SigSecret != "" && len(cfg.SigSecret) < 16 {
		return nil, errors.New("firewall: invalid SigSecret")
	}
	base := cfg.APIBase
	if base == "" {
		base = defaultAPIBase
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return nil, errors.New("firewall: invalid APIBase")
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, errors.New("firewall: APIBase must be https")
	}
	for _, k := range cfg.PinnedKeys {
		if isTestKey(k) && (reSiteKey.MatchString(cfg.SiteKey) || !local) {
			return nil, errors.New("firewall: TEST keys are allowed only for a non-canonical site key with a loopback API base")
		}
	}
	if cfg.SiteID != "" && !reSiteID.MatchString(cfg.SiteID) {
		return nil, errors.New("firewall: invalid SiteID")
	}
	if cfg.InitialFailMode != "" && cfg.InitialFailMode != "open" && cfg.InitialFailMode != "closed" {
		return nil, errors.New("firewall: invalid InitialFailMode")
	}
	f := &Firewall{
		siteKey:          cfg.SiteKey,
		secret:           cfg.SecretKey,
		sigSecret:        cfg.SigSecret,
		apiBase:          u.Scheme + "://" + u.Host,
		integration:      "go-net-http/" + Version,
		pinned:           cfg.PinnedKeys,
		failOpen:         cfg.InitialFailMode != "closed",
		now:              cfg.Now,
		store:            cfg.Store,
		log:              cfg.Logger,
		breaker:          &breaker{threshold: breakerThreshold, openFor: breakerOpenFor},
		siteID:           cfg.SiteID,
		siteIDPinned:     cfg.SiteID != "",
		canonicalSiteKey: reSiteKey.MatchString(cfg.SiteKey),
		refreshBase:      defaultRefreshBase,
		refreshExtra:     defaultRefreshExtra,
	}
	if cfg.RefreshInterval > 0 {
		f.refreshBase, f.refreshExtra = cfg.RefreshInterval, 0
	}
	if f.pinned == nil {
		f.pinned = PinnedPolicyKeys
	}
	if f.now == nil {
		f.now = time.Now
	}
	if f.store == nil {
		f.store = &memStore{}
	}
	if f.log == nil {
		f.log = slog.Default()
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{}
	}
	cp := *hc
	cp.CheckRedirect = noRedirect
	f.httpc = &cp
	return f, nil
}

func (f *Firewall) rand63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}

func newDecisionID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Middleware wraps next. Per request it strips every x-rg-* header, serves the reserved
// /__rg/ routes, decides, and either answers (block, redirect, challenge) or passes the
// request to next with the decision's headers set.
func (f *Firewall) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(w, r, next) })
}

// reqTarget is the raw request target as the server received it. It is r.RequestURI, never
// r.URL.Path (which is already unescaped).
func reqTarget(r *http.Request) string {
	if r.RequestURI != "" {
		return r.RequestURI
	}
	t := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		t += "?" + r.URL.RawQuery
	}
	return t
}

func acceptsHTML(r *http.Request) bool {
	for _, v := range r.Header.Values("Accept") {
		for _, part := range strings.Split(v, ",") {
			mt, _, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err == nil && strings.EqualFold(mt, "text/html") {
				return true
			}
		}
	}
	return false
}

func respond(w http.ResponseWriter, status int, extra map[string]string, vary bool) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	if vary {
		h.Add("Vary", "Cookie")
	}
	for k, v := range extra {
		if http.CanonicalHeaderKey(k) == "Cache-Control" {
			continue
		}
		h.Set(k, v)
	}
	w.WriteHeader(status)
	if status == http.StatusNoContent || (status >= 300 && status < 400) {
		return
	}
	_, _ = io.WriteString(w, http.StatusText(status)+"\n")
}

// cookieHeader builds a Set-Cookie value with the exact attributes of section 18.7.
func cookieHeader(name, value string, maxAge int64) string {
	return name + "=" + value + "; Max-Age=" + strconv.FormatInt(maxAge, 10) + "; " + cookieAttributes
}

// cookieSafe: the value uses only RFC 6265 cookie-octets.
func cookieSafe(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == ',' || c == ';' || c == '\\' {
			return false
		}
	}
	return true
}

func (f *Firewall) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	id := newDecisionID()
	// Read what travels in x-rg-* headers first: they are all stripped below.
	var actionToken string
	actionTokens := r.Header.Values("X-RG-Token")
	if len(actionTokens) == 1 {
		actionToken = actionTokens[0]
	} else if len(actionTokens) > 1 {
		actionToken = "!" // duplicates are ambiguous: malformed, never sent anywhere
	}
	sessionInit := r.Header.Get(sessionInitHeader)
	for name := range r.Header {
		if isRgHeader(name) {
			delete(r.Header, name)
		}
	}

	raw := reqTarget(r)
	req := Request{Host: r.Host, Method: r.Method, RawTarget: raw, FetchMode: "other", AcceptsHTML: acceptsHTML(r)}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Mode"), "navigate") {
		req.FetchMode = "navigate"
	}

	b := f.currentBundle()
	if b == nil {
		f.mu.RLock()
		notFound := f.notFound
		f.mu.RUnlock()
		if f.failOpen || notFound {
			f.logDecision(id, nil, "allow-no-bundle")
			r.Header.Set("X-RG-Verdict", "none")
			next.ServeHTTP(w, r)
			return
		}
		f.logDecision(id, nil, "block-no-bundle")
		respond(w, http.StatusServiceUnavailable, map[string]string{"Retry-After": "30"}, false)
		return
	}
	// red team E-2: a stale bundle is not trusted, so its kill switch is not either (v1.md 18.5): past expiresAt + 6 h the fail mode applies through Decide.
	if b.Disabled && f.now().Unix() <= b.ExpiresAt+staleGraceSeconds {
		// Kill switch: no rules, cookies, challenge, X-RG-Sig or verify call, whatever failMode says.
		next.ServeHTTP(w, r)
		return
	}
	now := f.now().Unix()
	vary := b.UsesCookies()

	if n := Normalize(raw); n.OK && now <= b.ExpiresAt+staleGraceSeconds {
		switch n.Path {
		case PathReturn:
			f.serveReturn(w, r, b, id, now)
			return
		case PathSession:
			f.serveSession(w, r, b, id, now, sessionInit)
			return
		}
		// The rest of the /__rg/ namespace belongs to the integration and never reaches the origin.
		if inReservedNamespace(n.Path) || inReservedNamespace(n.Collapsed) {
			f.logDecision(id, nil, "reserved-namespace")
			respond(w, http.StatusNotFound, nil, false)
			return
		}
	}

	host, hostOK := RequestHost(r.Host)
	sess := SessionState{Kind: "none"}
	if hostOK {
		sess, _ = f.sessionFromCookies(r, b, host, now)
	}
	d := Decide(b, req, sess, nil, now)
	if d.Kind == "needs-verify" {
		var out VerifyOutcome
		switch {
		case actionToken == "":
			out = VerifyOutcome{Kind: "absent"}
		default:
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), siteverifyTimeout+time.Second)
			out = f.siteverify(ctx, actionToken, host, d.Verify.ExpectedAction)
			cancel()
		}
		d = Decide(b, req, sess, &out, now)
	}
	f.logDecision(id, d.RuleIndex, d.Kind)

	switch d.Kind {
	case "allow":
		for k, v := range d.SetHeaders {
			dropSpellings(r.Header, k)
			r.Header.Set(k, v)
		}
		if sig, ok := f.sigHeader(b, host, r.Method, raw, d.SetHeaders, now); ok {
			dropSpellings(r.Header, "X-RG-Sig")
			r.Header.Set("X-RG-Sig", sig)
		}
		if vary {
			w.Header().Add("Vary", "Cookie")
		}
		next.ServeHTTP(w, r)
	case "block":
		respond(w, d.Status, nil, vary)
	case "redirect":
		respond(w, d.Status, map[string]string{"Location": d.Location}, vary)
	case "challenge":
		// setHeader values are origin-bound only: nothing but the action marker reaches the client.
		extra := map[string]string{}
		if v, ok := d.SetHeaders["X-RG-Action"]; ok {
			extra["X-RG-Action"] = v
		}
		if d.Status == http.StatusSeeOther {
			extra["Location"] = d.Location
			if rp := returnPathFor(raw); rp != "" {
				extra["Set-Cookie"] = cookieHeader(CookieReturnPath, rp, 600)
			}
		}
		respond(w, d.Status, extra, vary)
	default: // needs-verify cannot survive the second Decide; fail closed
		respond(w, http.StatusForbidden, nil, vary)
	}
}

// returnPathFor is the normalised path plus the raw query of a challenged GET, for the
// __Host-rg_r cookie; empty if it would not be a safe, cookie-safe return path of at most 2 KiB.
func returnPathFor(raw string) string {
	n := Normalize(raw)
	if !n.OK {
		return ""
	}
	cand := n.Path
	if q := strings.IndexByte(raw, '?'); q >= 0 {
		qs := raw[q:]
		if h := strings.IndexByte(qs, '#'); h >= 0 {
			qs = qs[:h]
		}
		cand += qs
	}
	if len(cand) > maxReturnPathLength || !IsSafeReturnPath(cand) || !cookieSafe(cand) {
		return ""
	}
	return cand
}

func (f *Firewall) logDecision(id string, rule *int, action string) {
	r := -1
	if rule != nil {
		r = *rule
	}
	f.log.Info("rg decision", "id", id, "rule", r, "action", action)
}

// sessionFromCookies verifies the clearance and session cookies for this host. A valid one
// wins (the higher level); a cookie that is present but invalid gives "invalid"; none gives
// "none".
func (f *Firewall) sessionFromCookies(r *http.Request, b *Payload, host string, now int64) (SessionState, *SessionClaims) {
	best := SessionState{Kind: "none"}
	var bestClaims *SessionClaims
	for _, name := range []string{CookieClearance, CookieSession} {
		c, err := r.Cookie(name)
		if err != nil || c.Value == "" {
			continue
		}
		var st SessionState
		var cl *SessionClaims
		if len(name)+1+len(c.Value) > maxCookieBytes {
			st = invalidSession()
		} else {
			st, cl = VerifySessionClaims(c.Value, b.TokenKeys, SessionExpect{SiteID: b.SiteID, Host: host},
				SessionBounds{MinIat: b.MinIat, RevokedJti: b.RevokedJti}, now)
		}
		switch {
		case st.Kind == "valid" && (best.Kind != "valid" || st.Lvl > best.Lvl):
			best, bestClaims = st, cl
		case st.Kind == "invalid" && best.Kind == "none":
			best = st
		}
	}
	return best, bestClaims
}

func hostCovered(b *Payload, host string) bool {
	for _, p := range b.Hosts {
		if hostnameMatches(host, p) {
			return true
		}
	}
	return false
}

// serveSession handles POST /__rg/session: the session token comes in X-RG-Session-Init and
// leaves in __Host-rg_s. No body is read.
func (f *Firewall) serveSession(w http.ResponseWriter, r *http.Request, b *Payload, id string, now int64, init string) {
	if r.Method != http.MethodPost {
		respond(w, http.StatusMethodNotAllowed, map[string]string{"Allow": "POST"}, false)
		return
	}
	host, ok := RequestHost(r.Host)
	if !ok || !hostCovered(b, host) {
		respond(w, http.StatusBadRequest, nil, false)
		return
	}
	st, cl := VerifySessionClaims(init, b.TokenKeys, SessionExpect{SiteID: b.SiteID, Host: host},
		SessionBounds{MinIat: b.MinIat, RevokedJti: b.RevokedJti}, now)
	if st.Kind != "valid" || st.Lvl != 0 || len(CookieSession)+1+len(init) > maxCookieBytes || !cookieSafe(init) {
		f.logDecision(id, nil, "session-refused")
		respond(w, http.StatusForbidden, nil, false)
		return
	}
	f.logDecision(id, nil, "session-set")
	respond(w, http.StatusNoContent, map[string]string{"Set-Cookie": cookieHeader(CookieSession, init, cl.Exp-now)}, false)
}

// serveReturn handles POST /__rg/return, the only route that reads a body: urlencoded, at most
// 4 KiB, the single field rg_clearance.
func (f *Firewall) serveReturn(w http.ResponseWriter, r *http.Request, b *Payload, id string, now int64) {
	if r.Method != http.MethodPost {
		respond(w, http.StatusMethodNotAllowed, map[string]string{"Allow": "POST"}, false)
		return
	}
	host, ok := RequestHost(r.Host)
	if !ok || !hostCovered(b, host) {
		respond(w, http.StatusBadRequest, nil, false)
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" {
		respond(w, http.StatusUnsupportedMediaType, nil, false)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, returnBodyLimit))
	if err != nil {
		respond(w, http.StatusRequestEntityTooLarge, nil, false)
		return
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil || len(vals) != 1 || len(vals[returnField]) != 1 {
		respond(w, http.StatusBadRequest, nil, false)
		return
	}
	tok := vals[returnField][0]
	st, cl := VerifySessionClaims(tok, b.TokenKeys, SessionExpect{SiteID: b.SiteID, Host: host},
		SessionBounds{MinIat: b.MinIat, RevokedJti: b.RevokedJti}, now)
	if st.Kind != "valid" || st.Lvl < 1 || len(CookieClearance)+1+len(tok) > maxCookieBytes || !cookieSafe(tok) {
		f.logDecision(id, nil, "return-refused")
		respond(w, http.StatusForbidden, nil, false)
		return
	}
	location := "/"
	if c, err := r.Cookie(CookieReturnPath); err == nil && IsSafeReturnPath(c.Value) {
		location = c.Value
	}
	f.logDecision(id, nil, "return")
	h := w.Header()
	h.Add("Set-Cookie", cookieHeader(CookieClearance, tok, cl.Exp-now))
	h.Add("Set-Cookie", cookieHeader(CookieReturnPath, "", 0))
	respond(w, http.StatusSeeOther, map[string]string{"Location": location}, false)
}

func inReservedNamespace(p string) bool { return p == "/__rg" || strings.HasPrefix(p, "/__rg/") }

// dropSpellings removes every client header that a CGI-style origin would read as the same name
// as `name`: the same name in any letter case, or with "_" where "-" is ("X_Tenant" and "X-Tenant"
// both become HTTP_X_TENANT). The integration's own value is then the only one.
func dropSpellings(h http.Header, name string) {
	want := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	for k := range h {
		if strings.ToLower(strings.ReplaceAll(k, "_", "-")) == want {
			delete(h, k)
		}
	}
}

// sigHeader is the X-RG-Sig value for an allow decision: only when the bundle asks for it and a
// SigSecret is configured. t,host,method,path,score,verdict,rule joined by LF, HMAC-SHA256.
func (f *Firewall) sigHeader(b *Payload, host, method, raw string, h map[string]string, now int64) (string, bool) {
	if !b.SigHeader {
		return "", false
	}
	if f.sigSecret == "" {
		if f.sigWarned.CompareAndSwap(false, true) {
			f.log.Warn("rg config warning", "reason", "sig-secret-missing")
		}
		return "", false
	}
	n := Normalize(raw)
	path := ""
	if n.OK {
		path = n.Path
	}
	t := strconv.FormatInt(now, 10)
	data := strings.Join([]string{t, host, method, path, h["X-RG-Score"], h["X-RG-Verdict"], h["X-RG-Rule"]}, "\n")
	mac := hmac.New(sha256.New, []byte(f.sigSecret))
	mac.Write([]byte(data))
	return "t=" + t + ",v1=" + hex.EncodeToString(mac.Sum(nil)), true
}
