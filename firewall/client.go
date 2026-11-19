package firewall

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	siteverifyTimeout   = 2 * time.Second
	bundleFetchTimeout  = 5 * time.Second
	maxSiteverifyBody   = 64 * 1024
	breakerThreshold    = 5
	breakerOpenFor      = 30 * time.Second
	defaultRefreshBase  = 60 * time.Second
	defaultRefreshExtra = 20 * time.Second
	coldRetryAfter      = 10 * time.Second // protocol v1 section 18.5: no more often than every 10 s while no bundle is held
)

var reTokenChars = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// validActionToken applies the pre-call check of the integration egress rules: length 20 to
// 4096 and only base64url characters and ".". A token that fails it is never sent anywhere.
func validActionToken(t string) bool {
	return len(t) >= 20 && len(t) <= 4096 && reTokenChars.MatchString(t)
}

// breaker opens after threshold consecutive failures and stays open for openFor.
type breaker struct {
	mu        sync.Mutex
	threshold int
	openFor   time.Duration
	fails     int
	openUntil time.Time
}

func (b *breaker) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !now.Before(b.openUntil)
}

func (b *breaker) success() {
	b.mu.Lock()
	b.fails = 0
	b.openUntil = time.Time{}
	b.mu.Unlock()
}

func (b *breaker) failure(now time.Time) {
	b.mu.Lock()
	b.fails++
	if b.fails >= b.threshold {
		b.openUntil = now.Add(b.openFor)
	}
	b.mu.Unlock()
}

// noRedirect: an integration never follows a redirect (a 307 or 308 would re-send the secret).
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// isConnectError reports whether err happened while establishing the connection (dial or DNS):
// nothing was sent, so a retry cannot spend a single-use token twice. Anything after the
// connection was made (a reset, EOF, a timeout) is never retried.
func isConnectError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		return true
	}
	var de *net.DNSError
	return errors.As(err, &de) && !de.IsTimeout
}

func (f *Firewall) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, f.apiBase+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-RG-Integration", f.integration)
	if f.secret != "" {
		req.Header.Set("Authorization", "Bearer "+f.secret)
	}
	return req, nil
}

// siteverify checks an action token with POST /v1/siteverify: 2 s timeout, one retry on a
// connection error only, a circuit breaker (5 consecutive failures open it for 30 s, during
// which nothing is sent and the outcome is "unreachable"). The token is checked for shape
// before any call. The outcome is "pass" only for success:true with this host and this
// action and a score in [0,1].
func (f *Firewall) siteverify(ctx context.Context, token, host, expectedAction string) VerifyOutcome {
	if !validActionToken(token) {
		return VerifyOutcome{Kind: "fail", Reason: "malformed-token"}
	}
	if f.secret == "" {
		return VerifyOutcome{Kind: "unreachable", Reason: "no-secret"}
	}
	if !f.breaker.allow(f.now()) {
		return VerifyOutcome{Kind: "unreachable", Reason: "breaker-open"}
	}
	// The secret travels only as the Authorization Bearer (newRequest): the edge answers
	// bad-request when it is also in the body.
	form := url.Values{"response": {token}}.Encode()
	// One 2 s budget covers every attempt, the send and the body read.
	actx, cancel := context.WithTimeout(ctx, siteverifyTimeout)
	defer cancel()
	for attempt := 0; attempt < 2; attempt++ {
		req, err := f.newRequest(actx, http.MethodPost, "/v1/siteverify", strings.NewReader(form))
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := f.httpc.Do(req)
		if err == nil {
			body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxSiteverifyBody+1))
			_ = resp.Body.Close()
			// A 429 is the edge answering (the site is over its siteverify rate limit, which a
			// flood of junk tokens can cause): fail this request closed and never count it, so it
			// cannot open the breaker into an onError allow bypass (red team E-1).
			if resp.StatusCode == http.StatusTooManyRequests {
				f.breaker.success()
				return VerifyOutcome{Kind: "fail", Reason: "rate-limited"}
			}
			if rerr != nil || len(body) > maxSiteverifyBody || resp.StatusCode != http.StatusOK {
				f.breaker.failure(f.now())
				return VerifyOutcome{Kind: "unreachable", Reason: "http-error"}
			}
			return f.readSiteverify(body, host, expectedAction)
		}
		if !isConnectError(err) {
			break // a timeout, or a failure after the request was sent: never retried
		}
	}
	f.breaker.failure(f.now())
	return VerifyOutcome{Kind: "unreachable", Reason: "network-error"}
}

// readSiteverify reads a 200 body strictly (protocol v1, section 7) and applies the
// relying-party checks: success is exactly true, the hostname is this request's host, the
// action is the rule's action, and a score in [0,1] is present.
func (f *Firewall) readSiteverify(body []byte, host, expectedAction string) VerifyOutcome {
	v, err := decodeJSON(body)
	m, ok := v.(obj)
	if err != nil || !ok {
		f.breaker.failure(f.now())
		return VerifyOutcome{Kind: "unreachable", Reason: "bad-body"}
	}
	f.breaker.success()
	if s, _ := m["success"].(bool); !s {
		return VerifyOutcome{Kind: "fail", Reason: "not-verified"}
	}
	hostname, hok := m["hostname"].(string)
	if !hok || hostname != host {
		return VerifyOutcome{Kind: "fail", Reason: "hostname-mismatch"}
	}
	action, aok := m["action"].(string)
	if !aok || action != expectedAction {
		return VerifyOutcome{Kind: "fail", Reason: "action-mismatch"}
	}
	score, sok := asFloat(m["score"])
	if !sok || score < 0 || score > 1 || math.IsNaN(score) {
		return VerifyOutcome{Kind: "fail", Reason: "score-invalid"}
	}
	return VerifyOutcome{Kind: "pass", Score: score}
}

var errNoPolicies = errors.New("bundle fetch: no policies (404)")

// fetchBundle does GET /v1/policies/<siteKey> with If-None-Match. notModified is true for a 304.
func (f *Firewall) fetchBundle(ctx context.Context) (served, etag string, notModified bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, bundleFetchTimeout)
	defer cancel()
	req, err := f.newRequest(ctx, http.MethodGet, "/v1/policies/"+f.siteKey, nil)
	if err != nil {
		return "", "", false, err
	}
	f.mu.RLock()
	prev := f.etag
	f.mu.RUnlock()
	if prev != "" {
		req.Header.Set("If-None-Match", prev)
	}
	resp, err := f.httpc.Do(req)
	if err != nil {
		return "", "", false, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return "", prev, true, nil
	case http.StatusOK:
	case http.StatusNotFound:
		return "", "", false, errNoPolicies
	case http.StatusUnauthorized, http.StatusForbidden:
		// A private bundle needs the site secret as a Bearer: a refusal is a configuration error,
		// logged once (never the secret), and counts as an outage like any other failure.
		f.authOnce.Do(func() {
			f.log.Error("rg config error", "reason", "bundle-unauthorized", "status", resp.StatusCode)
		})
		return "", "", false, errors.New("bundle fetch: unauthorized")
	default:
		return "", "", false, errors.New("bundle fetch: status " + http.StatusText(resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxServedBytes+1))
	if err != nil {
		return "", "", false, err
	}
	if len(body) > maxServedBytes {
		return "", "", false, errors.New("bundle fetch: too large")
	}
	return string(body), resp.Header.Get("ETag"), false, nil
}

// VersionStore remembers the highest bundle version accepted per site, so an older (rolled
// back) bundle is refused. The default is in memory; supply a durable one to survive restarts.
type VersionStore interface {
	Get(siteID string) int64
	Put(siteID string, version int64)
}

type memStore struct {
	mu sync.Mutex
	m  map[string]int64
}

func (s *memStore) Get(siteID string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[siteID]
}

func (s *memStore) Put(siteID string, v int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]int64{}
	}
	if v > s.m[siteID] {
		s.m[siteID] = v
	}
}

// refresh fetches, verifies and installs a bundle. A failure of any kind keeps the last good
// bundle (a bad signature is treated as no bundle).
func (f *Firewall) refresh() (any, error) {
	ctx := context.Background()
	served, etag, notModified, err := f.fetchBundle(ctx)
	now := f.now()
	// The not-found flag follows the latest outcome: any non-404 result clears it.
	f.mu.Lock()
	f.notFound = errors.Is(err, errNoPolicies) && f.payload == nil
	f.mu.Unlock()
	if err != nil {
		f.noteFailure(now, "fetch-error")
		return nil, err
	}
	if notModified {
		f.mu.Lock()
		f.nextRefresh = now.Add(f.refreshDelay())
		f.mu.Unlock()
		return nil, nil
	}
	f.mu.RLock()
	siteID := f.siteID
	f.mu.RUnlock()
	var minVersion int64
	if siteID != "" {
		minVersion = f.store.Get(siteID)
	}
	expect := BundleExpect{SiteID: siteID, AnySite: siteID == ""}
	if f.siteIDPinned || f.canonicalSiteKey {
		expect.SiteKey = f.siteKey // a canonical production key always checks the bundle's siteKey
	}
	res := VerifyBundle(served, f.pinned, now.Unix(), minVersion, expect)
	if !res.OK {
		f.noteFailure(now, "bundle-"+res.Reason)
		return nil, errors.New("bundle rejected: " + res.Reason)
	}
	f.mu.Lock()
	if f.siteID == "" {
		f.siteID = res.Payload.SiteID // trust on first use: the pinned key signed it
	}
	f.payload = res.Payload
	f.etag = etag
	f.nextRefresh = now.Add(f.refreshDelay())
	f.lastFail = time.Time{}
	f.notFound = false
	f.mu.Unlock()
	f.store.Put(res.Payload.SiteID, res.Payload.Version)
	return nil, nil
}

func (f *Firewall) noteFailure(now time.Time, why string) {
	f.mu.Lock()
	f.lastFail = now
	if f.payload != nil {
		f.nextRefresh = now.Add(f.refreshDelay())
	}
	f.mu.Unlock()
	f.log.Warn("rg bundle refresh failed", "reason", why)
}

func (f *Firewall) refreshDelay() time.Duration {
	d := f.refreshBase
	if f.refreshExtra > 0 {
		d += time.Duration(f.rand63n(int64(f.refreshExtra)))
	}
	return d
}

// currentBundle returns the last good bundle. With none cached it fetches one (single-flight);
// with one cached it serves it and refreshes in the background when due.
func (f *Firewall) currentBundle() *Payload {
	f.mu.RLock()
	p, due, failedAt := f.payload, !f.nextRefresh.After(f.now()), f.lastFail
	f.mu.RUnlock()
	if p != nil {
		if due {
			go func() { _, _ = f.flight.Do("bundle", f.refresh) }()
		}
		return p
	}
	if !failedAt.IsZero() && f.now().Sub(failedAt) < coldRetryAfter {
		return nil
	}
	_, _ = f.flight.Do("bundle", f.refresh)
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.payload
}
