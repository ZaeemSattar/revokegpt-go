package firewall

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const loginRule = `[{"type":"requireToken","action":"login","threshold":0.5}]`

func loginBundle(e *env) {
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/login", `["POST"]`, loginRule, "")}, "")
}

var goodToken = map[string]string{"X-RG-Token": "goodtoken-goodtoken-goodtoken"}

// The secret travels only as the Authorization Bearer: the edge answers bad-request when it is also in the body.
func TestSiteverifySecretOnlyInBearer(t *testing.T) {
	e := newEnv(t)
	loginBundle(e)
	var bodies []string
	var auths []string
	_, _, h := e.firewall(func(c *Config) {
		c.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/siteverify") {
				b, _ := io.ReadAll(r.Body)
				bodies = append(bodies, string(b))
				auths = append(auths, r.Header.Get("Authorization"))
				r.Body = io.NopCloser(strings.NewReader(string(b)))
			}
			return http.DefaultTransport.RoundTrip(r)
		})}
	})
	if rec := do(h, "POST", "/login", goodToken, nil); rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	if len(bodies) != 1 || auths[0] != "Bearer rgsk_test" {
		t.Fatalf("calls %v %v", bodies, auths)
	}
	form, _ := url.ParseQuery(bodies[0])
	if _, has := form["secret"]; has || strings.Contains(bodies[0], "rgsk_") || form.Get("response") == "" {
		t.Fatalf("body carries the secret or lacks the token: %q", bodies[0])
	}
}

func TestNoRetryAfterTheRequestWasSent(t *testing.T) {
	for name, err := range map[string]error{
		"reset after send": &net.OpError{Op: "read", Err: io.ErrUnexpectedEOF},
		"eof":              io.EOF,
		"write":            &net.OpError{Op: "write", Err: io.ErrClosedPipe},
	} {
		e := newEnv(t)
		loginBundle(e)
		var attempts atomic.Int32
		_, _, h := e.firewall(func(c *Config) {
			c.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/siteverify") {
					attempts.Add(1)
					return nil, err
				}
				return http.DefaultTransport.RoundTrip(r)
			})}
		})
		do(h, "POST", "/login", goodToken, nil)
		if attempts.Load() != 1 {
			t.Fatalf("%s: %d attempts, want 1", name, attempts.Load())
		}
	}
}

type blockedBody struct{ ctx context.Context }

func (b blockedBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (b blockedBody) Close() error             { return nil }

// A connect error followed by a slow body still ends inside ONE 2 s budget.
func TestSiteverifyBudgetCoversRetryAndBody(t *testing.T) {
	e := newEnv(t)
	loginBundle(e)
	var attempts atomic.Int32
	_, _, h := e.firewall(func(c *Config) {
		c.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if !strings.HasSuffix(r.URL.Path, "/siteverify") {
				return http.DefaultTransport.RoundTrip(r)
			}
			if attempts.Add(1) == 1 {
				return nil, &net.OpError{Op: "dial", Err: io.ErrNoProgress} // refused: one retry
			}
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: blockedBody{r.Context()}}, nil
		})}
	})
	start := time.Now()
	rec := do(h, "POST", "/login", goodToken, nil)
	took := time.Since(start)
	if attempts.Load() != 2 {
		t.Fatalf("%d attempts, want 2 (refused, then one retry)", attempts.Load())
	}
	if took < 1900*time.Millisecond || took > 2600*time.Millisecond {
		t.Fatalf("took %v, want about 2 s total", took)
	}
	if rec.Code == 200 {
		t.Fatalf("a cut body must not pass")
	}
}

func TestMissingBundleRetriedNoOftenerThanEvery10s(t *testing.T) {
	e := newEnv(t)
	e.status = 500
	_, _, h := e.firewall()
	do(h, "GET", "/x", nil, nil)
	if e.bundleCalls.Load() != 1 {
		t.Fatalf("first: %d", e.bundleCalls.Load())
	}
	e.clock.Add(9)
	do(h, "GET", "/x", nil, nil)
	if e.bundleCalls.Load() != 1 {
		t.Fatalf("after 9 s: %d fetches, want 1", e.bundleCalls.Load())
	}
	e.clock.Add(2)
	do(h, "GET", "/x", nil, nil)
	if e.bundleCalls.Load() != 2 {
		t.Fatalf("after 11 s: %d fetches, want 2", e.bundleCalls.Load())
	}
}

func TestBundleUnauthorizedLoggedOnceAsConfigError(t *testing.T) {
	e := newEnv(t)
	e.status = 401
	var got atomic.Value
	_, _, h := e.firewall(func(c *Config) {
		c.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			got.Store(r.Header.Get("Authorization"))
			return http.DefaultTransport.RoundTrip(r)
		})}
	})
	for i := 0; i < 3; i++ {
		if rec := do(h, "GET", "/x", nil, nil); rec.Code != 200 { // initialFailMode open
			t.Fatalf("code %d", rec.Code)
		}
		e.clock.Add(11)
	}
	if got.Load() != "Bearer rgsk_test" {
		t.Fatalf("bundle fetch Authorization %v", got.Load())
	}
	logs := e.logs.String()
	if n := strings.Count(logs, "bundle-unauthorized"); n != 1 {
		t.Fatalf("config error logged %d times:\n%s", n, logs)
	}
	if strings.Contains(logs, "rgsk_") {
		t.Fatalf("secret in logs: %s", logs)
	}
}

func TestSetHeaderDropsUnderscoreSpellings(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/t", `["*"]`, `[{"type":"setHeader","name":"x-tenant","value":"mine"},{"type":"allow"}]`, "")}, "")
	_, seen, h := e.firewall()
	req := newReq("GET", "/t")
	req.Header["X_Tenant"] = []string{"evil"}
	req.Header["x-tenant"] = []string{"evil2"}
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen.headers.Get("X-Tenant") != "mine" || len(seen.headers["X_Tenant"]) != 0 || len(seen.headers["x-tenant"]) != 0 {
		t.Fatalf("headers toward origin: %v", seen.headers)
	}
}

func TestBundleMayCarrySigHeader(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, nil, `"sigHeader":true,`)
	_, _, h := e.firewall()
	if rec := do(h, "GET", "/x", nil, nil); rec.Code != 200 {
		t.Fatalf("a bundle with sigHeader was refused: %d", rec.Code)
	}
}

func newReq(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = tHost
	return r
}

func TestBundleDisabledKillSwitchPassesEverythingThrough(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, []string{ruleJSON("aaaaaaaa", "/**", `["*"]`, `[{"type":"block","status":403}]`, "")}, `"disabled":true,"sigHeader":true,`)
	_, seen, h := e.firewall(func(c *Config) { c.SigSecret = "0123456789abcdef0123" })
	rec := do(h, "GET", "/admin/x", nil, nil)
	if rec.Code != 200 || seen.calls != 1 {
		t.Fatalf("disabled bundle did not pass through: %d calls=%d", rec.Code, seen.calls)
	}
	if seen.headers.Get("X-RG-Sig") != "" || seen.headers.Get("X-RG-Verdict") != "" || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("kill switch touched the request: %v", seen.headers)
	}
}

func TestBundleDisabledMustBeBoolean(t *testing.T) {
	e := newEnv(t)
	e.setBundle(1, nil, `"disabled":"yes",`)
	_, _, h := e.firewall(func(c *Config) { c.InitialFailMode = "closed" })
	if rec := do(h, "GET", "/x", nil, nil); rec.Code == 200 {
		t.Fatalf("a non-boolean disabled bundle was accepted")
	}
	e.setBundle(1, nil, `"disabled":false,`)
	_, _, h = e.firewall(func(c *Config) { c.InitialFailMode = "closed" })
	if rec := do(h, "GET", "/x", nil, nil); rec.Code != 200 {
		t.Fatalf("disabled:false refused: %d", rec.Code)
	}
}
