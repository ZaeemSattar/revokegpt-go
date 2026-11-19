package firewall

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	tSiteID  = "3f1c2a9e-5b7d-4e2f-9a1b-0c8d7e6f5a4b"
	tSiteKey = "rgpk_7Hq2LmZ9xK4aBc8DeFgH"
	tNow     = int64(1790000000)
	tHost    = "example.com"
	// notBefore is now-300, and a bundle may be valid for at most 86400 s from notBefore.
	tValidity = int64(86100)
)

func seedKey(label string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte(label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type env struct {
	t        *testing.T
	bundlePK ed25519.PrivateKey
	bundleK  Key
	sessPK   ed25519.PrivateKey
	sessK    Key

	api          *httptest.Server
	mu           sync.Mutex
	served       string
	status       int
	bundleCalls  atomic.Int32
	verifyCalls  atomic.Int32
	verifyScore  float64
	verifyStatus int
	verifyAction string
	logs         bytes.Buffer
	clock        atomic.Int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, status: 200, verifyScore: 0.9, verifyStatus: 200, verifyAction: "login"}
	pub, priv := seedKey("go-test-bundle")
	e.bundlePK = priv
	e.bundleK = Key{Kid: KidOfPublicKey(pub), Alg: "Ed25519", Pub: b64(pub), NotAfter: 4102444800}
	spub, spriv := seedKey("go-test-session")
	e.sessPK = spriv
	e.sessK = Key{Kid: KidOfPublicKey(spub), Alg: "Ed25519", Pub: b64(spub), NotAfter: 4102444800}
	e.clock.Store(tNow)
	e.api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/policies/"+tSiteKey:
			e.bundleCalls.Add(1)
			e.mu.Lock()
			served, status := e.served, e.status
			e.mu.Unlock()
			if status != 200 {
				w.WriteHeader(status)
				return
			}
			_, _ = io.WriteString(w, served)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/siteverify":
			e.verifyCalls.Add(1)
			if r.Header.Get("Authorization") != "Bearer rgsk_test" || !strings.HasPrefix(r.Header.Get("X-RG-Integration"), "go-net-http/") {
				w.WriteHeader(401)
				return
			}
			if e.verifyStatus != 200 {
				w.WriteHeader(e.verifyStatus)
				return
			}
			_ = r.ParseForm()
			ok := r.PostForm.Get("response") == "goodtoken-goodtoken-goodtoken"
			if !ok {
				_, _ = io.WriteString(w, `{"success":false,"error-codes":["invalid-input-response"]}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"success":true,"score":%v,"action":%q,"hostname":%q}`, e.verifyScore, e.verifyAction, tHost)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(e.api.Close)
	return e
}

func ruleJSON(id, path, methods, actions, extra string) string {
	return fmt.Sprintf(`{"id":%q,"name":"r-%s","enabled":true,"match":{"hosts":["example.com"],"path":%q,"methods":%s},%s"actions":%s,"onError":"block"}`,
		id, id, path, methods, extra, actions)
}

func (e *env) payload(version int64, policies []string, extra string) string {
	return fmt.Sprintf(`{"v":1,"siteId":%q,"siteKey":%q,"challengeBase":"https://challenge.revokegpt.test","version":%d,"issuedAt":%d,"notBefore":%d,"expiresAt":%d,"failMode":"closed",%s"minIat":0,"revokedJti":[],"session":{"ttl":1800,"max":43200,"clearanceTtl":1800},"hosts":["example.com","*.example.com"],"tokenKeys":[{"kid":%q,"alg":"Ed25519","pub":%q,"notAfter":4102444800}],"policies":[%s]}`,
		tSiteID, tSiteKey, version, tNow, tNow-300, tNow+tValidity, extra, e.sessK.Kid, e.sessK.Pub, strings.Join(policies, ","))
}

func (e *env) sign(payload string) string {
	msg := append([]byte(policySignatureDomain), payload...)
	sig := ed25519.Sign(e.bundlePK, msg)
	return fmt.Sprintf(`{"alg":"Ed25519","kid":%q,"payload":%q,"sig":%q}`, e.bundleK.Kid, b64([]byte(payload)), b64(sig))
}

func (e *env) setBundle(version int64, policies []string, extra string) {
	e.mu.Lock()
	e.served = e.sign(e.payload(version, policies, extra))
	e.mu.Unlock()
}

func (e *env) session(host string, lvl int, iat, exp int64, jti string) string {
	p := fmt.Sprintf(`{"sid":%q,"host":%q,"iat":%d,"exp":%d,"max":43200,"lvl":%d,"sc":2,"jti":%q}`, tSiteID, host, iat, exp, lvl, jti)
	sig := ed25519.Sign(e.sessPK, append([]byte(sessionSignatureDomain), p...))
	return "v1." + e.sessK.Kid + "." + b64([]byte(p)) + "." + b64(sig)
}

type originSeen struct {
	mu      sync.Mutex
	calls   int
	headers http.Header
	path    string
}

func (e *env) firewall(extra ...func(*Config)) (*Firewall, *originSeen, http.Handler) {
	cfg := Config{
		SiteKey: tSiteKey, SecretKey: "rgsk_test", APIBase: e.api.URL,
		PinnedKeys: []Key{e.bundleK},
		Now:        func() time.Time { return time.Unix(e.clock.Load(), 0) },
		Logger:     slog.New(slog.NewTextHandler(&e.logs, nil)),
	}
	for _, x := range extra {
		x(&cfg)
	}
	f, err := New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	seen := &originSeen{}
	h := f.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.calls++
		seen.headers = r.Header.Clone()
		seen.path = r.RequestURI
		seen.mu.Unlock()
		_, _ = io.WriteString(w, "origin")
	}))
	return f, seen, h
}

func do(h http.Handler, method, target string, hdr map[string]string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	req.Host = tHost
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAllowStripsClientZCHeadersAndSetsRule(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/open/**", `["*"]`, `[{"type":"scoreHeader"},{"type":"allow"}]`, "")}, "")
	_, seen, h := e.firewall()
	req := httptest.NewRequest("GET", "/open/x?q=1", nil)
	req.Host = tHost
	req.Header["X-Rg-Score"] = []string{"100", "100"}
	req.Header["X_RG_Verdict"] = []string{"pass"}
	req.Header.Set("X-RG-Token", "sneaky")
	req.Header.Set("X-Real", "kept")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "origin" {
		t.Fatalf("code %d body %q", rec.Code, rec.Body.String())
	}
	if seen.headers.Get("X-RG-Rule") != "0" || seen.headers.Get("X-RG-Score") != "0" || seen.headers.Get("X-RG-Verdict") != "none" {
		t.Fatalf("headers toward origin: %v", seen.headers)
	}
	if len(seen.headers["X_RG_Verdict"]) != 0 || seen.headers.Get("X-RG-Token") != "" || seen.headers.Get("X-Real") != "kept" {
		t.Fatalf("strip failed: %v", seen.headers)
	}
}

func TestRawTargetPathDifferential(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/admin/**", `["*"]`, `[{"type":"block","status":403}]`, "")}, `"onNonCanonical":"block",`)
	_, seen, h := e.firewall()
	srv := httptest.NewServer(h)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	// Targets written as raw request lines, so no client library touches them. "//admin" and the
	// dot-segment forms reach the server verbatim and are matched on RequestURI, never r.URL.Path.
	cases := []struct {
		target string
		code   int
	}{
		{"/admin/x", 403},
		{"/admin%2Fsecret", 403},
		{"/Admin/../admin/x", 403},
		{"//admin", 403},
		{"/admin;jsessionid=1", 403},
		{"/%2e%2e/admin", 403},
		{"/admin/%C0%AF", 403},
		{"/public", 200},
	}
	for _, c := range cases {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", c.target)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("%s: %v", c.target, err)
		}
		_ = resp.Body.Close()
		_ = conn.Close()
		if resp.StatusCode != c.code {
			t.Errorf("GET %s: %d, want %d", c.target, resp.StatusCode, c.code)
		}
	}
	_ = seen
}

func TestNonCanonicalBlockWritesPolicy(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/admin/**", `["*"]`, `[{"type":"block","status":403}]`, "")}, "")
	_, seen, h := e.firewall()
	if rec := do(h, "POST", "/admin%2Fsecret", nil, nil); rec.Code != 403 {
		t.Fatalf("POST non-canonical: %d", rec.Code)
	}
	rec := do(h, "GET", "/admin%2Fsecret", nil, nil)
	if rec.Code != 200 || seen.headers.Get("X-RG-Path") != "non-canonical" || seen.headers.Get("X-RG-Verdict") != "none" {
		t.Fatalf("GET non-canonical: %d %v", rec.Code, seen.headers)
	}
}

func TestRequireTokenFlow(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/login", `["POST"]`, `[{"type":"requireToken","action":"login","threshold":0.5}]`, "")}, "")
	_, seen, h := e.firewall()

	// No token: 403, no call.
	if rec := do(h, "POST", "/login", nil, nil); rec.Code != 403 || e.verifyCalls.Load() != 0 {
		t.Fatalf("no token: %d calls %d", rec.Code, e.verifyCalls.Load())
	}
	// Malformed tokens: 403, no call.
	for _, tok := range []string{"short", strings.Repeat("a", 4097), "has space has space has space", "bad+chars+bad+chars+bad+chars"} {
		if rec := do(h, "POST", "/login", map[string]string{"X-RG-Token": tok}, nil); rec.Code != 403 {
			t.Fatalf("malformed %q: %d", tok, rec.Code)
		}
	}
	if e.verifyCalls.Load() != 0 {
		t.Fatalf("malformed tokens reached siteverify: %d calls", e.verifyCalls.Load())
	}
	// Good token: allowed, score header toward origin.
	rec := do(h, "POST", "/login", map[string]string{"X-RG-Token": "goodtoken-goodtoken-goodtoken"}, nil)
	if rec.Code != 200 || seen.headers.Get("X-RG-Score") != "90" || seen.headers.Get("X-RG-Verdict") != "pass" || seen.headers.Get("X-RG-Rule") != "0" {
		t.Fatalf("good token: %d %v", rec.Code, seen.headers)
	}
	// Wrong token: success false, 403.
	if rec := do(h, "POST", "/login", map[string]string{"X-RG-Token": "wrongtoken-wrongtoken-wrong"}, nil); rec.Code != 403 {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	// Score below the threshold: 403.
	e.verifyScore = 0.3
	if rec := do(h, "POST", "/login", map[string]string{"X-RG-Token": "goodtoken-goodtoken-goodtoken"}, nil); rec.Code != 403 {
		t.Fatalf("low score: %d", rec.Code)
	}
	// Wrong action in the result: 403.
	e.verifyScore, e.verifyAction = 0.9, "signup"
	if rec := do(h, "POST", "/login", map[string]string{"X-RG-Token": "goodtoken-goodtoken-goodtoken"}, nil); rec.Code != 403 {
		t.Fatalf("action mismatch: %d", rec.Code)
	}
}

func TestBodyIsNeverReadOutsideReturnRoute(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/login", `["POST"]`, `[{"type":"requireToken","action":"login","threshold":0.5}]`, "")}, "")
	_, _, h := e.firewall()
	body := &trackedBody{}
	req := httptest.NewRequest("POST", "/login", body)
	req.Host = tHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 || body.reads.Load() != 0 {
		t.Fatalf("code %d, body reads %d", rec.Code, body.reads.Load())
	}
}

type trackedBody struct{ reads atomic.Int32 }

func (b *trackedBody) Read([]byte) (int, error) { b.reads.Add(1); return 0, io.EOF }

func TestBreakerOpensAfterFiveFailures(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/login", `["POST"]`, `[{"type":"requireToken","action":"login","threshold":0.5}]`, "")}, "")
	e.verifyStatus = 500
	_, _, h := e.firewall()
	for i := 0; i < 5; i++ {
		if rec := do(h, "POST", "/login", map[string]string{"X-RG-Token": "goodtoken-goodtoken-goodtoken"}, nil); rec.Code != 403 {
			t.Fatalf("failure %d: %d", i, rec.Code)
		}
	}
	if got := e.verifyCalls.Load(); got != 5 {
		t.Fatalf("calls before open: %d", got)
	}
	do(h, "POST", "/login", map[string]string{"X-RG-Token": "goodtoken-goodtoken-goodtoken"}, nil)
	if got := e.verifyCalls.Load(); got != 5 {
		t.Fatalf("breaker open but a call was made: %d", got)
	}
	// After 30 s the breaker closes and the API is tried again.
	e.clock.Add(31)
	e.verifyStatus = 200
	if rec := do(h, "POST", "/login", map[string]string{"X-RG-Token": "goodtoken-goodtoken-goodtoken"}, nil); rec.Code != 200 {
		t.Fatalf("after reset: %d", rec.Code)
	}
}

// Red team E-1: a 429 (the site over its siteverify rate limit, caused by a junk-token flood) is a
// fail, never a breaker failure, so an onError allow rule cannot be opened into a bypass.
func TestSiteverify429NeverOpensBreaker(t *testing.T) {
	e := newEnv(t)
	rule := strings.Replace(ruleJSON("aaaaaaaa", "/login", `["POST"]`, `[{"type":"requireToken","action":"login","threshold":0.5}]`, ""), `"onError":"block"`, `"onError":"allow"`, 1)
	e.setBundle(1, []string{rule}, "")
	e.verifyStatus = 429
	_, _, h := e.firewall()
	for i := 0; i < 10; i++ {
		if rec := do(h, "POST", "/login", map[string]string{"X-RG-Token": "goodtoken-goodtoken-goodtoken"}, nil); rec.Code != 403 {
			t.Fatalf("request %d under 429: %d, want 403", i, rec.Code)
		}
	}
	if got := e.verifyCalls.Load(); got != 10 {
		t.Fatalf("breaker opened under 429: %d calls, want 10", got)
	}
}

func TestRetryOnConnectionErrorOnly(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/login", `["POST"]`, `[{"type":"requireToken","action":"login","threshold":0.5}]`, "")}, "")
	var attempts atomic.Int32
	f, _, h := e.firewall(func(c *Config) {
		c.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/siteverify") {
				attempts.Add(1)
				return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("connection refused")}
			}
			return http.DefaultTransport.RoundTrip(r)
		})}
	})
	_ = f
	do(h, "POST", "/login", map[string]string{"X-RG-Token": "goodtoken-goodtoken-goodtoken"}, nil)
	if attempts.Load() != 2 {
		t.Fatalf("connection error: %d attempts, want 2 (one retry)", attempts.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestChallengeNavigationAndFetch(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/private/**", `["*"]`, `[{"type":"challengePage","minLevel":1}]`, "")}, "")
	_, _, h := e.firewall()
	nav := map[string]string{"Sec-Fetch-Mode": "navigate", "Accept": "text/html,application/xhtml+xml"}
	rec := do(h, "GET", "/private/a?x=1", nav, nil)
	if rec.Code != 303 || rec.Header().Get("Location") != "https://challenge.revokegpt.test/c/"+tSiteKey+"?h=example.com" {
		t.Fatalf("navigation: %d %v", rec.Code, rec.Header())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Vary") != "Cookie" {
		t.Fatalf("headers: %v", rec.Header())
	}
	if sc := rec.Header().Get("Set-Cookie"); sc != "__Host-rg_r=/private/a?x=1; Max-Age=600; HttpOnly; Secure; SameSite=Lax; Path=/" {
		t.Fatalf("return cookie: %q", sc)
	}
	// fetch / XHR, a POST and HEAD never get a redirect.
	for _, c := range []struct {
		method string
		hdr    map[string]string
	}{
		{"GET", map[string]string{"Sec-Fetch-Mode": "cors", "Accept": "application/json"}},
		{"GET", map[string]string{"Sec-Fetch-Mode": "navigate", "Accept": "application/json"}},
		{"POST", nav},
		{"HEAD", nav},
	} {
		rec := do(h, c.method, "/private/a", c.hdr, nil)
		if rec.Code != 403 || rec.Header().Get("X-RG-Action") != "challenge" || rec.Header().Get("Location") != "" ||
			rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Set-Cookie") != "" {
			t.Fatalf("%s %v: %d %v", c.method, c.hdr, rec.Code, rec.Header())
		}
	}
}

func TestSessionCookieSatisfiesChallengeAndHostBinding(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/private/**", `["*"]`, `[{"type":"challengePage","minLevel":1}]`, "")}, "")
	_, seen, h := e.firewall()
	clearance := e.session(tHost, 1, tNow-10, tNow+1000, "AAAAAAAAAAAAAAAA")
	rec := do(h, "GET", "/private/a", map[string]string{"Cookie": CookieClearance + "=" + clearance}, nil)
	if rec.Code != 200 || seen.headers.Get("X-RG-Rule") != "0" {
		t.Fatalf("valid clearance: %d", rec.Code)
	}
	// A level 0 session is below minLevel 1.
	sess := e.session(tHost, 0, tNow-10, tNow+1000, "BBBBBBBBBBBBBBBB")
	if rec := do(h, "GET", "/private/a", map[string]string{"Cookie": CookieSession + "=" + sess}, nil); rec.Code != 403 {
		t.Fatalf("level 0 session: %d", rec.Code)
	}
	// A token issued for a.example.com is refused on example.com, and no siteverify call is made.
	other := e.session("a.example.com", 1, tNow-10, tNow+1000, "CCCCCCCCCCCCCCCC")
	if rec := do(h, "GET", "/private/a", map[string]string{"Cookie": CookieClearance + "=" + other}, nil); rec.Code != 403 {
		t.Fatalf("other host: %d", rec.Code)
	}
	if e.verifyCalls.Load() != 0 {
		t.Fatal("a token caused a siteverify call")
	}
	// Expired.
	old := e.session(tHost, 1, tNow-5000, tNow-1, "DDDDDDDDDDDDDDDD")
	if rec := do(h, "GET", "/private/a", map[string]string{"Cookie": CookieClearance + "=" + old}, nil); rec.Code != 403 {
		t.Fatalf("expired: %d", rec.Code)
	}
}

func TestReturnRoute(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/private/**", `["*"]`, `[{"type":"challengePage","minLevel":1}]`, "")}, "")
	_, _, h := e.firewall()
	clearance := e.session(tHost, 1, tNow-10, tNow+1000, "AAAAAAAAAAAAAAAA")
	form := func(tok string) io.Reader { return strings.NewReader(url.Values{"rg_clearance": {tok}}.Encode()) }
	ct := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	post := func(retCookie string, tok string) *httptest.ResponseRecorder {
		hdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		if retCookie != "" {
			hdr["Cookie"] = CookieReturnPath + "=" + retCookie
		}
		return do(h, "POST", "/__rg/return", hdr, form(tok))
	}

	rec := post("/private/a?x=1", clearance)
	if rec.Code != 303 || rec.Header().Get("Location") != "/private/a?x=1" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("return: %d %v", rec.Code, rec.Header())
	}
	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) != 2 || cookies[0] != "__Host-rg_c="+clearance+"; Max-Age=1000; HttpOnly; Secure; SameSite=Lax; Path=/" ||
		cookies[1] != "__Host-rg_r=; Max-Age=0; HttpOnly; Secure; SameSite=Lax; Path=/" {
		t.Fatalf("cookies: %q", cookies)
	}
	// Open-redirect inputs all land on "/".
	for _, bad := range []string{"//evil.com", `/\evil.com`, "https://evil.com", "/%0d%0aSet-Cookie:x", "/__rg/return", "/a/../b", "evil.com"} {
		rec := post(bad, clearance)
		if rec.Code != 303 || rec.Header().Get("Location") != "/" {
			t.Fatalf("return cookie %q: %d Location %q", bad, rec.Code, rec.Header().Get("Location"))
		}
	}
	// A clearance for another host, a level 0 session, garbage, a bad content type, a big body.
	if rec := post("", e.session("a.example.com", 1, tNow-10, tNow+1000, "EEEEEEEEEEEEEEEE")); rec.Code != 403 {
		t.Fatalf("other host: %d", rec.Code)
	}
	if rec := post("", e.session(tHost, 0, tNow-10, tNow+1000, "FFFFFFFFFFFFFFFF")); rec.Code != 403 {
		t.Fatalf("level 0 as clearance: %d", rec.Code)
	}
	if rec := post("", "garbage"); rec.Code != 403 {
		t.Fatalf("garbage: %d", rec.Code)
	}
	if rec := do(h, "POST", "/__rg/return", map[string]string{"Content-Type": "application/json"}, strings.NewReader("{}")); rec.Code != 415 {
		t.Fatalf("json: %d", rec.Code)
	}
	if rec := do(h, "POST", "/__rg/return", ct, strings.NewReader("rg_clearance="+strings.Repeat("a", 5000))); rec.Code != 413 {
		t.Fatalf("big: %d", rec.Code)
	}
	if rec := do(h, "GET", "/__rg/return", nil, nil); rec.Code != 405 {
		t.Fatalf("GET: %d", rec.Code)
	}
}

func TestSessionRoute(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, nil, "")
	_, _, h := e.firewall()
	sess := e.session(tHost, 0, tNow-10, tNow+1000, "BBBBBBBBBBBBBBBB")
	rec := do(h, "POST", "/__rg/session", map[string]string{"X-RG-Session-Init": sess}, nil)
	if rec.Code != 204 || rec.Header().Get("Set-Cookie") != "__Host-rg_s="+sess+"; Max-Age=1000; HttpOnly; Secure; SameSite=Lax; Path=/" ||
		rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	if rec := do(h, "POST", "/__rg/session", map[string]string{"X-RG-Session-Init": "v1.nope"}, nil); rec.Code != 403 {
		t.Fatalf("bad token: %d", rec.Code)
	}
	if rec := do(h, "POST", "/__rg/session", nil, nil); rec.Code != 403 {
		t.Fatalf("no token: %d", rec.Code)
	}
}

func TestBundleCache(t *testing.T) {
	t.Run("one fetch for 100 concurrent cold calls", func(t *testing.T) {
		e := newEnv(t)
		e.setBundle(1, nil, "")
		_, _, h := e.firewall()
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if rec := do(h, "GET", "/x", nil, nil); rec.Code != 200 {
					t.Errorf("code %d", rec.Code)
				}
			}()
		}
		wg.Wait()
		if got := e.bundleCalls.Load(); got != 1 {
			t.Fatalf("%d bundle fetches, want 1", got)
		}
	})
	t.Run("no bundle yet: open by default with verdict none, 503 when closed, 404 passes", func(t *testing.T) {
		e := newEnv(t)
		e.status = 500
		_, seen, h := e.firewall()
		if rec := do(h, "GET", "/x", nil, nil); rec.Code != 200 || seen.headers.Get("X-RG-Verdict") != "none" {
			t.Fatalf("default open: %d %v", rec.Code, seen.headers)
		}
		_, _, hc := e.firewall(func(c *Config) { c.InitialFailMode = "closed" })
		if rec := do(hc, "GET", "/x", nil, nil); rec.Code != 503 {
			t.Fatalf("closed: %d", rec.Code)
		}
		e.status = 404
		_, _, hn := e.firewall(func(c *Config) { c.InitialFailMode = "closed" })
		if rec := do(hn, "GET", "/x", nil, nil); rec.Code != 200 {
			t.Fatalf("404 no policies: %d", rec.Code)
		}
	})
	t.Run("a bad signature is no bundle", func(t *testing.T) {
		e := newEnv(t)
		e.setBundle(1, nil, "")
		e.mu.Lock()
		e.served = strings.Replace(e.served, `"sig":"`, `"sig":"AAAA`, 1)
		e.mu.Unlock()
		_, _, h := e.firewall(func(c *Config) { c.InitialFailMode = "closed" })
		if rec := do(h, "GET", "/x", nil, nil); rec.Code != 503 {
			t.Fatalf("bad sig: %d", rec.Code)
		}
	})
	t.Run("refresh failure keeps the last good bundle; rollback refused; fail mode after 6h", func(t *testing.T) {
		e := newEnv(t)
		e.setBundle(5, []string{ruleJSON("aaaaaaaa", "/x", `["*"]`, `[{"type":"block","status":404}]`, "")}, "")
		f, _, h := e.firewall(func(c *Config) { c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) })
		f.refreshExtra = 0
		if rec := do(h, "GET", "/x", nil, nil); rec.Code != 404 {
			t.Fatalf("first: %d", rec.Code)
		}
		// Server error: last good stays.
		e.mu.Lock()
		e.status = 500
		e.mu.Unlock()
		e.clock.Add(61)
		if _, err := f.flight.Do("bundle", f.refresh); err == nil {
			t.Fatal("expected refresh error")
		}
		if rec := do(h, "GET", "/x", nil, nil); rec.Code != 404 {
			t.Fatalf("after 500: %d", rec.Code)
		}
		// A validly signed OLDER version is refused where state exists.
		e.setBundle(4, nil, "")
		e.mu.Lock()
		e.status = 200
		e.mu.Unlock()
		e.clock.Add(61)
		if _, err := f.flight.Do("bundle", f.refresh); err == nil {
			t.Fatal("rollback accepted")
		}
		if rec := do(h, "GET", "/x", nil, nil); rec.Code != 404 {
			t.Fatalf("after rollback: %d", rec.Code)
		}
		// Past expiresAt + 6h the bundle's failMode (closed) applies.
		e.mu.Lock()
		e.status = 500
		e.mu.Unlock()
		e.clock.Store(tNow + tValidity + staleGraceSeconds + 1)
		if rec := do(h, "GET", "/x", nil, nil); rec.Code != 503 {
			t.Fatalf("expired: %d", rec.Code)
		}
	})
	t.Run("a newer version replaces the cached one", func(t *testing.T) {
		e := newEnv(t)
		e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/x", `["*"]`, `[{"type":"block","status":404}]`, "")}, "")
		f, _, h := e.firewall()
		f.refreshExtra = 0
		do(h, "GET", "/x", nil, nil)
		e.setBundle(2, nil, "")
		e.clock.Add(61)
		if _, err := f.flight.Do("bundle", f.refresh); err != nil {
			t.Fatal(err)
		}
		if rec := do(h, "GET", "/x", nil, nil); rec.Code != 200 {
			t.Fatalf("v2: %d", rec.Code)
		}
	})
}

func TestLogsNeverHoldTokensCookiesOrQueries(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{
		ruleJSON("aaaaaaaa", "/login", `["POST"]`, `[{"type":"requireToken","action":"login","threshold":0.5}]`, ""),
		ruleJSON("bbbbbbbb", "/private/**", `["*"]`, `[{"type":"challengePage","minLevel":1}]`, ""),
	}, "")
	_, _, h := e.firewall()
	clearance := e.session(tHost, 1, tNow-10, tNow+1000, "AAAAAAAAAAAAAAAA")
	do(h, "POST", "/login?secretquery=hunter2", map[string]string{"X-RG-Token": "goodtoken-goodtoken-goodtoken"}, nil)
	do(h, "GET", "/private/a?secretquery=hunter2", map[string]string{"Cookie": CookieClearance + "=" + clearance}, nil)
	do(h, "POST", "/__rg/return", map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		strings.NewReader(url.Values{"rg_clearance": {clearance}}.Encode()))
	out := e.logs.String()
	if out == "" {
		t.Fatal("no log output")
	}
	for _, secret := range []string{"goodtoken", "hunter2", clearance, "secretquery", "rgsk_test", "Bearer"} {
		if strings.Contains(out, secret) {
			t.Fatalf("log holds %q:\n%s", secret, out)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []Config{
		{},
		{SiteKey: "nope"},
		{SiteKey: tSiteKey, SecretKey: "rgmk_x"},
		{SiteKey: tSiteKey, APIBase: "http://api.example.com"},
		{SiteKey: tSiteKey, APIBase: "https://user:pw@api.example.com"},
		{SiteKey: tSiteKey, APIBase: "https://api.example.com/v1"},
		{SiteKey: tSiteKey, InitialFailMode: "maybe"},
		{SiteKey: tSiteKey, SiteID: "not-a-uuid"},
	}
	for i, c := range bad {
		if _, err := New(c); err == nil {
			t.Errorf("config %d accepted: %+v", i, c)
		}
	}
	if _, err := New(Config{SiteKey: tSiteKey, APIBase: "http://localhost:8080"}); err != nil {
		t.Errorf("localhost http refused: %v", err)
	}
}

func TestSingleflightSharesOneCall(t *testing.T) {
	var g flightGroup
	var calls atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = g.Do("k", func() (any, error) { calls.Add(1); <-release; return 1, nil })
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("%d calls", calls.Load())
	}
}

func TestSetHeaderIsOriginOnly(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{
		ruleJSON("aaaaaaaa", "/private/**", `["*"]`, `[{"type":"setHeader","name":"x-tier","value":"gold"},{"type":"setHeader","name":"cache-control","value":"public"},{"type":"challengePage","minLevel":1}]`, ""),
		ruleJSON("bbbbbbbb", "/blocked", `["*"]`, `[{"type":"setHeader","name":"x-tier","value":"gold"},{"type":"block","status":403}]`, ""),
	}, "")
	_, _, h := e.firewall()
	nav := map[string]string{"Sec-Fetch-Mode": "navigate", "Accept": "text/html"}
	for _, rec := range []*httptest.ResponseRecorder{
		do(h, "GET", "/private/a", nav, nil), do(h, "GET", "/private/a", nil, nil), do(h, "GET", "/blocked", nil, nil),
	} {
		if rec.Header().Get("X-Tier") != "" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("leak or override: %d %v", rec.Code, rec.Header())
		}
	}
}

func TestTestKeysOnlyForLoopbackConformance(t *testing.T) {
	ok := Config{SiteKey: "rgpk_conformance", APIBase: "http://127.0.0.1:4610", PinnedKeys: TestPolicyKeys()}
	if _, err := New(ok); err != nil {
		t.Fatalf("conformance config refused: %v", err)
	}
	ok.APIBase = "http://localhost:4610"
	if _, err := New(ok); err != nil {
		t.Fatalf("localhost refused: %v", err)
	}
	bad := []Config{
		{SiteKey: tSiteKey, APIBase: "http://127.0.0.1:4610", PinnedKeys: TestPolicyKeys()},
		{SiteKey: "rgpk_conformance", APIBase: "https://api.revokegpt.com", PinnedKeys: TestPolicyKeys()},
		{SiteKey: "rgpk_conformance", PinnedKeys: TestPolicyKeys()},
		{SiteKey: tSiteKey, APIBase: "https://api.revokegpt.com", PinnedKeys: TestPolicyKeys()},
		{SiteKey: "rgpk_conformance", APIBase: "https://evil.example", PinnedKeys: TestPolicyKeys()[1:]},
	}
	for i, c := range bad {
		if _, err := New(c); err == nil {
			t.Errorf("combination %d accepted", i)
		}
	}
}

func TestCanonicalSiteKeyChecksBundleSiteKey(t *testing.T) {
	e := newEnv(t)
	e.mu.Lock()
	e.served = e.sign(strings.Replace(e.payload(1, nil, ""), tSiteKey, "rgpk_AAAAAAAAAAAAAAAAAAAA", 1))
	e.mu.Unlock()
	_, _, h := e.firewall(func(c *Config) { c.InitialFailMode = "closed" })
	if rec := do(h, "GET", "/x", nil, nil); rec.Code != 503 {
		t.Fatalf("foreign siteKey accepted: %d", rec.Code)
	}
}

func TestNotFoundFlagClearedByLaterFailure(t *testing.T) {
	e := newEnv(t)
	e.status = 404
	f, _, h := e.firewall(func(c *Config) { c.InitialFailMode = "closed" })
	if rec := do(h, "GET", "/x", nil, nil); rec.Code != 200 {
		t.Fatalf("404 should pass: %d", rec.Code)
	}
	e.mu.Lock()
	e.status = 500
	e.mu.Unlock()
	e.clock.Add(3)
	_, _ = f.flight.Do("bundle", f.refresh)
	if rec := do(h, "GET", "/x", nil, nil); rec.Code != 503 {
		t.Fatalf("5xx after 404 must follow closed: %d", rec.Code)
	}
}

func TestReservedNamespaceAndReturnBody(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, nil, "")
	_, seen, h := e.firewall()
	for _, p := range []string{"/__rg/anything", "/__rg", "//__rg/x", "/__rg/return/x", "/a/../__rg/x"} {
		if rec := do(h, "GET", p, nil, nil); rec.Code != 404 || seen.calls != 0 {
			t.Fatalf("%s: %d, origin calls %d", p, rec.Code, seen.calls)
		}
	}
	clearance := e.session(tHost, 1, tNow-10, tNow+1000, "AAAAAAAAAAAAAAAA")
	ct := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if rec := do(h, "POST", "/__rg/return", ct, strings.NewReader("rg_clearance="+clearance+"&x=1")); rec.Code != 400 || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("extra field accepted: %d", rec.Code)
	}
}

// With DisableGeneralOptionsHandler, "OPTIONS *" reaches the middleware and is a 400.
func TestOptionsAsteriskReachesMiddleware(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, nil, "")
	_, _, h := e.firewall()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.DisableGeneralOptionsHandler = true
	srv.Start()
	defer srv.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprint(conn, "OPTIONS * HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("OPTIONS *: %d", resp.StatusCode)
	}
}

func sigWant(secret string, t int64, host, method, path, score, verdict, rule string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(fmt.Sprintf("%d\n%s\n%s\n%s\n%s\n%s\n%s", t, host, method, path, score, verdict, rule)))
	return fmt.Sprintf("t=%d,v1=%s", t, hex.EncodeToString(m.Sum(nil)))
}

func TestSigHeaderKnownAnswer(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, nil, `"sigHeader":true,`)
	const secret = "0123456789abcdef-secret"
	_, seen, h := e.firewall(func(c *Config) { c.SigSecret = secret })
	rec := do(h, "GET", "/x", map[string]string{"X-RG-Sig": "forged"}, nil)
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	want := sigWant(secret, e.clock.Load(), tHost, "GET", "/x",
		seen.headers.Get("X-RG-Score"), seen.headers.Get("X-RG-Verdict"), seen.headers.Get("X-RG-Rule"))
	if got := seen.headers.Get("X-RG-Sig"); got != want {
		t.Fatalf("sig %q want %q", got, want)
	}
}

func TestSigHeaderFalseUnsignedAndStripped(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, nil, `"sigHeader":false,`)
	_, seen, h := e.firewall(func(c *Config) { c.SigSecret = "0123456789abcdef-secret" })
	do(h, "GET", "/x", map[string]string{"X-RG-Sig": "forged"}, nil)
	if v := seen.headers.Get("X-RG-Sig"); v != "" {
		t.Fatalf("unsigned expected, got %q", v)
	}
}

func TestSigHeaderNoSecretWarnsOnce(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, nil, `"sigHeader":true,`)
	_, seen, h := e.firewall()
	do(h, "GET", "/x", nil, nil)
	do(h, "GET", "/y", nil, nil)
	if v := seen.headers.Get("X-RG-Sig"); v != "" {
		t.Fatalf("no sig expected, got %q", v)
	}
	if n := strings.Count(e.logs.String(), "sig-secret-missing"); n != 1 {
		t.Fatalf("warnings %d, want 1", n)
	}
}

func TestSigSecretTooShort(t *testing.T) {
	_, err := New(Config{SiteKey: tSiteKey, SigSecret: "short"})
	if err == nil || !strings.Contains(err.Error(), "invalid SigSecret") {
		t.Fatalf("err %v", err)
	}
}
