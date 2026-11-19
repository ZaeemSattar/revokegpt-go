package firewall

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Documents the Go runtime facts listed in the README: net/http answers these 400 itself, before
// any handler (so before the firewall) runs. A refusal, never an allow.
func TestRuntimeAnswersBadHostHeadersBeforeHandler(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer srv.Close()
	for _, req := range []string{
		"GET /ok HTTP/1.1\r\nHost: example.com\r\nHost: FORGED\r\nConnection: close\r\n\r\n",
		"GET /ok HTTP/1.1\r\nHost: b\xc3\xbccher.example\r\nConnection: close\r\n\r\n",
	} {
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprint(conn, req)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		_ = conn.Close()
		if err != nil || resp.StatusCode != 400 {
			t.Fatalf("%q: %v %v", req, resp, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("handler ran")
	}
}
