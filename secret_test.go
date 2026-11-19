package revokegpt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// canaryKey is a valid secret key (the checksum is computed) whose parts are easy to grep for.
func canaryKey() string {
	body := "rgsk_CANARYkeyid1_CANARYsecretCANARYsecretCANARYxx"
	n := crc32.ChecksumIEEE([]byte(body))
	var sum [6]byte
	for i := 5; i >= 0; i-- {
		sum[i] = base62[n%62]
		n /= 62
	}
	return body + string(sum[:])
}

// leaks reports a part of the secret found in out.
func leaks(out string) string {
	key := canaryKey()
	for _, part := range []string{key, key[5:], "CANARY", "secretCANARY"} {
		if strings.Contains(out, part) {
			return part
		}
	}
	return ""
}

func canaryClient(t *testing.T, s *stub, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{WithHTTPClient(&http.Client{Transport: s})}, opts...)
	c, err := New(canaryKey(), testEndpoint, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTheCanaryKeyIsValid(t *testing.T) {
	if _, err := New(canaryKey(), testEndpoint); err != nil {
		t.Fatal(err)
	}
}

func TestSecretNeverAppearsInAnyFormattedForm(t *testing.T) {
	c := canaryClient(t, &stub{handler: respond(200, "{}")})
	type holder struct {
		Name   string
		Client *Client
		Value  Client
	}
	// fmt cannot call a method on an unexported field, so the secret sits behind a pointer in an unexported
	// type: whatever holds a Client (a value, a pointer, a struct, a map) prints a placeholder or an address.
	h := holder{"x", c, *c}
	subjects := []any{c, *c, h, &h, []any{c, *c}, map[string]any{"k": c}}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%p", "%T", "%10.3v", "%-8s", "%08d", "%t"}
	for _, subject := range subjects {
		for _, verb := range verbs {
			if got := leaks(fmt.Sprintf(verb, subject)); got != "" {
				t.Errorf("%s of %T leaks %q", verb, subject, got)
			}
		}
		if got := leaks(fmt.Sprint(subject)) + leaks(fmt.Sprintln(subject)); got != "" {
			t.Errorf("Sprint of %T leaks %q", subject, got)
		}
	}
	for _, s := range []string{c.String(), c.GoString(), fmt.Sprintf("%v", c.LogValue())} {
		if s != redacted {
			t.Errorf("not the placeholder: %q", s)
		}
	}
}

func TestSecretNeverAppearsInLogs(t *testing.T) {
	c := canaryClient(t, &stub{handler: respond(200, "{}")})
	for name, mk := range map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
	} {
		var buf bytes.Buffer
		l := slog.New(mk(&buf))
		l.Info("client", "client", c, "value", *c, "secret", c.c.secret, slog.Group("g", "c", c))
		l.With("client", c).WithGroup("grp").Error("again", "err", errors.New("x"), "c", *c)
		if got := leaks(buf.String()); got != "" {
			t.Errorf("%s handler leaks %q: %s", name, got, buf.String())
		}
		if !strings.Contains(buf.String(), "redacted") {
			t.Errorf("%s handler: no placeholder: %s", name, buf.String())
		}
	}
}

func TestSecretNeverAppearsInJSON(t *testing.T) {
	c := canaryClient(t, &stub{handler: respond(200, "{}")})
	for _, v := range []any{c, *c, c.c.secret, map[string]any{"c": c}, []any{c}} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if got := leaks(string(b)); got != "" {
			t.Errorf("%T leaks %q in %s", v, got, b)
		}
	}
	// No exported field on the client, and none on the types it holds that could carry the key.
	if n := reflect.TypeOf(*c).NumField(); n != 1 || reflect.TypeOf(*c).Field(0).IsExported() {
		t.Fatal("Client has an exported field")
	}
	b, _ := json.Marshal(c)
	if string(b) != `"`+redacted+`"` {
		t.Fatalf("Client marshals as %s", b)
	}
}

func TestSecretNeverAppearsInErrors(t *testing.T) {
	key := canaryKey()
	var seen []string
	note := func(err error) {
		if err == nil {
			t.Error("expected an error")
			return
		}
		seen = append(seen, err.Error(), fmt.Sprintf("%v|%+v|%#v|%q", err, err, err, err), fmt.Errorf("wrapped: %w", err).Error())
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("not an input error: %v", err)
		}
	}
	// A wrong secret that is the key with one corrupted checksum character, a management key, and a key in the
	// endpoint, in the query, and as userinfo.
	_, err := New(key[:len(key)-1]+"!", testEndpoint)
	note(err)
	_, err = New("rgmk"+key[4:], testEndpoint)
	note(err)
	for _, ep := range []string{
		"https://" + key + "@api.revokegpt.test/v1/siteverify",
		"https://user:" + key + "@api.revokegpt.test/v1/siteverify",
		"https://api.revokegpt.test/v1/siteverify?secret=" + key,
		"https://api.revokegpt.test/" + key + "#x",
		"ftp://" + key,
		"http://" + key + ".example/siteverify",
	} {
		_, err = New(key, ep)
		note(err)
	}
	for _, o := range []Option{WithTimeout(0), WithTimeout(-1), WithHTTPClient(nil)} {
		_, err = New(key, testEndpoint, o)
		note(err)
	}
	for _, e := range []error{&Error{Code: "network-error"}, &Error{Code: "bad-request", Status: 400, RequestID: "req_1"}} {
		seen = append(seen, e.Error(), fmt.Sprintf("%+v %#v", e, e))
	}
	for _, s := range seen {
		if got := leaks(s); got != "" {
			t.Errorf("an error text leaks %q: %s", got, s)
		}
	}
}

func TestSecretOnlyTravelsInTheFormBody(t *testing.T) {
	var cap []string
	s := &stub{handler: func(r *http.Request) (*http.Response, error) {
		cap = append(cap, r.URL.String(), r.Method, r.Host, fmt.Sprint(r.Header))
		return respond(200, `{"success":true,"hostname":"shop.example","score":0.9}`)(r)
	}}
	c := canaryClient(t, s)
	min := 0.5
	out := c.Verify(context.Background(), "tok_abc", VerifyOptions{ExpectedHostname: "shop.example", MinScore: &min})
	if !out.OK {
		t.Fatalf("%+v", out)
	}
	for _, x := range cap {
		if got := leaks(x); got != "" {
			t.Errorf("request metadata leaks %q: %s", got, x)
		}
	}
	if !strings.Contains(s.bodies[0], "secret=rgsk_CANARYkeyid1_") {
		t.Fatalf("the secret is not in the form: %q", s.bodies[0])
	}
	// Every outcome of every failure path, printed in every form, is clean as well.
	paths := map[string]*stub{
		"network":      {handler: func(*http.Request) (*http.Response, error) { return nil, errors.New("connection reset") }},
		"500":          {handler: respond(500, `{"error":"`+canaryKey()+`"}`)},
		"redirect":     {handler: respond(307, "")},
		"not verified": {handler: respond(200, `{"success":false}`)},
		"reflecting":   {handler: respond(200, `{"success":true,"hostname":"shop.example"}`)},
	}
	for name, st := range paths {
		for _, o := range []VerifyOptions{{}, {ExpectedHostname: "shop.example"}, {ExpectedHostname: "shop.example", RemoteIP: "nope"}} {
			out := canaryClient(t, st).Verify(context.Background(), "tok_abc", o)
			if got := leaks(fmt.Sprintf("%v %+v %#v", out, out, out)); got != "" {
				t.Errorf("%s: outcome leaks %q", name, got)
			}
		}
	}
}
