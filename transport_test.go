package revokegpt

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const passBody = `{"success":true,"hostname":"shop.example"}`

func realClient(t *testing.T, srv string, opts ...Option) *Client {
	t.Helper()
	c, err := New(fixtureSecret(t), srv+"/v1/siteverify", opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func verifyShop(c *Client) VerifyOutcome {
	return c.Verify(context.Background(), "tok_abc", VerifyOptions{ExpectedHostname: "shop.example"})
}

// within runs f and fails when it takes longer than limit.
func within(t *testing.T, limit time.Duration, f func()) time.Duration {
	t.Helper()
	start := time.Now()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(limit + 2*time.Second):
		t.Fatalf("still running after %v (limit %v)", time.Since(start), limit)
	}
	took := time.Since(start)
	if took > limit {
		t.Fatalf("took %v, limit %v", took, limit)
	}
	return took
}

// dribble listens on a TCP port and, for each connection, writes prefix then one byte every 10 ms until the
// client closes the connection. It returns the base URL.
func dribble(t *testing.T, prefix string, fill byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				// Read the request head so the client has finished sending.
				br := bufio.NewReader(conn)
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				if _, err := conn.Write([]byte(prefix)); err != nil {
					return
				}
				for {
					time.Sleep(10 * time.Millisecond)
					if _, err := conn.Write([]byte{fill}); err != nil {
						return
					}
				}
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

func TestTimeoutIsATotalBoundOnADribbledHeader(t *testing.T) {
	// The status line arrives, then one header byte every 10 ms and never the end of the headers. A per-read
	// timeout would never fire.
	base := dribble(t, "HTTP/1.1 200 OK\r\nX-Slow: ", 'a')
	c := realClient(t, base, WithTimeout(300*time.Millisecond))
	var out VerifyOutcome
	took := within(t, 1500*time.Millisecond, func() { out = verifyShop(c) })
	if out.OK || out.Reason != "network-error" {
		t.Fatalf("%+v", out)
	}
	if took < 250*time.Millisecond {
		t.Fatalf("returned early: %v", took)
	}
}

func TestTimeoutIsATotalBoundOnADribbledBody(t *testing.T) {
	base := dribble(t, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n", ' ')
	c := realClient(t, base, WithTimeout(300*time.Millisecond))
	var out VerifyOutcome
	within(t, 1500*time.Millisecond, func() { out = verifyShop(c) })
	if out.OK || out.Reason != "network-error" {
		t.Fatalf("%+v", out)
	}
}

func TestTimeoutBoundsASlowConnectOrDNS(t *testing.T) {
	// A dial (or a resolver) that only ends when its context does.
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}}
	c, err := New(fixtureSecret(t), "https://slow-dns.invalid/v1/siteverify", WithHTTPClient(hc), WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	var out VerifyOutcome
	within(t, 1000*time.Millisecond, func() { out = verifyShop(c) })
	if out.OK || out.Reason != "network-error" {
		t.Fatalf("%+v", out)
	}
}

func TestTimeoutHoldsEvenWhenTheTransportIgnoresItsContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var started atomic.Int32
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		started.Add(1)
		<-release // a transport that never looks at the request context
		return nil, errors.New("released")
	})
	c, err := New(fixtureSecret(t), testEndpoint, WithHTTPClient(&http.Client{Transport: rt}), WithTimeout(150*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	var out VerifyOutcome
	within(t, 800*time.Millisecond, func() { out = verifyShop(c) })
	if out.OK || out.Reason != "network-error" || started.Load() != 1 {
		t.Fatalf("%+v started %d", out, started.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAContextDeadlineShorterThanTheTimeoutWins(t *testing.T) {
	base := dribble(t, "HTTP/1.1 200 OK\r\nX-Slow: ", 'a')
	c := realClient(t, base, WithTimeout(10*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	var out VerifyOutcome
	within(t, 800*time.Millisecond, func() {
		out = c.Verify(ctx, "tok_abc", VerifyOptions{ExpectedHostname: "shop.example"})
	})
	if out.Reason != "network-error" {
		t.Fatalf("%+v", out)
	}
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(passBody))
	}))
	defer other.Close()
	var bodies []string
	var mu sync.Mutex
	for _, code := range []int{301, 302, 303, 307, 308} {
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(r.Body)
			mu.Lock()
			bodies = append(bodies, buf.String())
			mu.Unlock()
			http.Redirect(w, r, other.URL+"/v1/siteverify", code)
		}))
		// The caller's client follows redirects; the SDK's copy must not.
		given := &http.Client{}
		c := realClient(t, first.URL, WithHTTPClient(given))
		out := verifyShop(c)
		first.Close()
		if out.OK || out.Reason != "http-error" {
			t.Fatalf("%d: %+v", code, out)
		}
		if given.CheckRedirect != nil {
			t.Fatal("the caller's client was changed")
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("a redirect was followed %d times (the secret would have gone along)", hits.Load())
	}
}

func TestACappedBodyIsReadWhileStreamingAndRefused(t *testing.T) {
	var written atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := bytes.Repeat([]byte("x"), 8192)
		for {
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	c := realClient(t, srv.URL, WithTimeout(5*time.Second))
	var out VerifyOutcome
	within(t, 3*time.Second, func() { out = verifyShop(c) })
	if out.OK || out.Reason != "http-error" {
		t.Fatalf("%+v", out)
	}
	// The SDK stopped reading at the cap (plus what the kernel and the transport buffer); an unbounded read of an
	// endless body would never return.
	if w := written.Load(); w > 16<<20 {
		t.Fatalf("the server wrote %d bytes", w)
	}
}

func TestAnExactlyCapSizedBodyIsParsed(t *testing.T) {
	pad := strings.Repeat(" ", maxResponseBytes-len(passBody))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(passBody + pad)) }))
	defer srv.Close()
	if out := verifyShop(realClient(t, srv.URL)); !out.OK {
		t.Fatalf("%+v", out)
	}
	over := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(passBody + pad + " ")) }))
	defer over.Close()
	if out := verifyShop(realClient(t, over.URL)); out.OK || out.Reason != "http-error" {
		t.Fatalf("%+v", out)
	}
}

func TestAnEncodedResponseIsRefusedAndIdentityIsRequested(t *testing.T) {
	var accept atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept.Store(r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		_, _ = zw.Write([]byte(passBody))
		_ = zw.Close()
	}))
	defer srv.Close()
	out := verifyShop(realClient(t, srv.URL))
	if out.OK || out.Reason != "network-error" || accept.Load() != "identity" {
		t.Fatalf("%+v accept %v", out, accept.Load())
	}
}

func TestHangUps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, _ := w.(http.Hijacker).Hijack()
		if r.URL.Path == "/v1/siteverify" {
			_ = conn.Close() // before the headers
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n{\"success\":")
		_ = buf.Flush()
		_ = conn.Close()
	}))
	defer srv.Close()
	for _, path := range []string{"/v1/siteverify", "/v1/other"} {
		c, err := New(fixtureSecret(t), srv.URL+path)
		if err != nil {
			t.Fatal(err)
		}
		if out := verifyShop(c); out.OK || out.Reason != "network-error" {
			t.Fatalf("%s: %+v", path, out)
		}
	}
}

func TestTheDefaultClientIgnoresProxyEnvironmentAndTheCallersClientIsCopied(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:3128")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	c, err := New(fixtureSecret(t), testEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.c.http.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatal("the SDK's own client reads proxy environment variables")
	}
	if tr == http.DefaultTransport {
		t.Fatal("the SDK's own client shares the default transport")
	}
	if c.c.http.CheckRedirect == nil || c.c.http.Jar != nil {
		t.Fatal("redirects or cookies are enabled")
	}
	// An injected client is copied, with its transport and timeout, but without a redirect policy or a jar.
	given := &http.Client{Timeout: 3 * time.Second, Transport: &stub{}}
	d, _ := New(fixtureSecret(t), testEndpoint, WithHTTPClient(given))
	if d.c.http == given || d.c.http.Timeout != 3*time.Second || d.c.http.Transport != given.Transport {
		t.Fatal("not a copy of the given client")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(passBody)) }))
	defer srv.Close()
	c := realClient(t, srv.URL)
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok := fmt.Sprintf("tok_%d", i)
			if out := c.Verify(context.Background(), tok, VerifyOptions{ExpectedHostname: "shop.example"}); !out.OK {
				bad.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d failed", bad.Load())
	}
}

func TestTheRequestShapeOverRealHTTP(t *testing.T) {
	var got struct {
		method, path, ctype, ua, accept, auth, body string
		clen                                        int64
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		got.method, got.path, got.ctype, got.ua, got.accept, got.auth = r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("User-Agent"), r.Header.Get("Accept"), r.Header.Get("Authorization")
		got.body, got.clen = buf.String(), r.ContentLength
		_, _ = w.Write([]byte(passBody))
	}))
	defer srv.Close()
	if out := verifyShop(realClient(t, srv.URL)); !out.OK {
		t.Fatalf("%+v", out)
	}
	if got.method != "POST" || got.path != "/v1/siteverify" || got.ctype != "application/x-www-form-urlencoded" ||
		got.ua != "revokegpt-go/"+Version || got.accept != "application/json" || got.auth != "" || got.clen != int64(len(got.body)) {
		t.Fatalf("%+v", got)
	}
}
