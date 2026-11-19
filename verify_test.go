package revokegpt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// scripted turns the response of an sdk-http case into a RoundTripper handler.
func scripted(t *testing.T, resp map[string]any) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		if resp == nil {
			t.Error("a request was sent for a case with no response")
			return nil, errors.New("no response")
		}
		if ms, ok := resp["delayMs"].(float64); ok {
			select {
			case <-time.After(time.Duration(ms) * time.Millisecond):
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		if resp["hangup"] == "before-headers" {
			return nil, errors.New("connection reset")
		}
		var body []byte
		switch {
		case resp["bodyBase64"] != nil:
			body, _ = base64.StdEncoding.DecodeString(resp["bodyBase64"].(string))
		case resp["bodyRepeat"] != nil:
			rep := obj(resp["bodyRepeat"])
			body = bytes.Repeat([]byte(rep["chunk"].(string)), int(rep["times"].(float64)))
		case resp["body"] == nil:
		default:
			if s, ok := resp["body"].(string); ok {
				body = []byte(s)
			} else {
				body, _ = json.Marshal(resp["body"])
			}
		}
		var rd io.Reader = bytes.NewReader(body)
		if resp["hangup"] == "mid-body" {
			rd = io.MultiReader(bytes.NewReader(body[:len(body)/2]), errReader{})
		}
		h := http.Header{}
		for k, v := range obj(resp["headers"]) {
			h.Set(k, v.(string))
		}
		status := int(resp["status"].(float64))
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(rd), Request: r}, nil
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func optionsOf(t *testing.T, raw map[string]any) VerifyOptions {
	t.Helper()
	o, ok := toVerifyOptions(raw)
	if !ok {
		t.Fatalf("options %v", raw)
	}
	return o
}

// toVerifyOptions is the wire-neutral options of an sdk-http case as VerifyOptions.
func toVerifyOptions(m map[string]any) (VerifyOptions, bool) {
	var o VerifyOptions
	for k, v := range m {
		switch k {
		case "expectedHostname":
			o.ExpectedHostname, _ = v.(string)
		case "remoteip":
			o.RemoteIP, _ = v.(string)
		case "sitekey":
			o.SiteKey, _ = v.(string)
		case "expectedAction":
			a := v.(string)
			o.ExpectedAction = &a
		case "minScore":
			f := v.(float64)
			o.MinScore = &f
		case "expectedApp":
			a := obj(v)
			o.ExpectedApp = &ExpectedApp{Platform: a["platform"].(string), ID: a["id"].(string)}
		default:
			return o, false
		}
	}
	return o, true
}

func TestSDKHTTPVerifyCases(t *testing.T) {
	secret := fixtureSecret(t)
	ran := 0
	for _, c := range loadVector(t, "sdk-http.json").Cases {
		if c["call"] != "verify" {
			continue
		}
		ran++
		c := c
		t.Run(c["name"].(string), func(t *testing.T) {
			args, ex := obj(c["args"]), obj(c["expected"])
			s := &stub{handler: scripted(t, obj(c["response"]))}
			var opts []Option
			if ms, ok := args["timeoutMs"].(float64); ok {
				opts = append(opts, WithTimeout(time.Duration(ms)*time.Millisecond))
			}
			client := stubClient(t, s, opts...)
			out := client.Verify(context.Background(), args["token"].(string), optionsOf(t, obj(args["options"])))

			want := obj(ex["outcome"])
			reason, _ := want["reason"].(string)
			if out.OK != (want["ok"] == true) || out.Reason != reason {
				t.Fatalf("outcome ok=%v reason=%q, want %v", out.OK, out.Reason, want)
			}
			req := obj(ex["request"])
			if req == nil {
				if s.calls() != 0 {
					t.Fatal("a request was sent")
				}
				return
			}
			if s.calls() != 1 {
				t.Fatalf("calls %d", s.calls())
			}
			r := s.reqs[0]
			if r.Method != req["method"] || r.URL.Path != req["path"] || r.Header.Get("Content-Type") != req["contentType"] {
				t.Fatalf("request %s %s %s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
			}
			if r.URL.RawQuery != "" || strings.Contains(r.URL.String(), "rgsk_") || r.Header.Get("Authorization") != "" {
				t.Fatalf("the secret is placed outside the form: %s", r.URL)
			}
			if got := r.Header.Get("User-Agent"); got != "revokegpt-go/"+Version {
				t.Fatalf("user agent %q", got)
			}
			form, err := url.ParseQuery(s.bodies[0])
			if err != nil {
				t.Fatal(err)
			}
			wantForm := map[string]string{"secret": secret}
			for k, v := range obj(req["form"]) {
				wantForm[k] = v.(string)
			}
			if len(form) != len(wantForm) {
				t.Fatalf("form %v, want %v", form, wantForm)
			}
			for k, v := range wantForm {
				if len(form[k]) != 1 || form[k][0] != v {
					t.Fatalf("form field %q", k)
				}
			}
		})
	}
	if ran != 41 {
		t.Fatalf("%d verify cases, want 41", ran)
	}
}

func TestVerifyResultIsParsedForAPass(t *testing.T) {
	body := `{"success":true,"challenge_ts":"2026-11-01T12:00:00Z","hostname":"shop.example","score":0.9,"action":"login","reasons":["A"],"error-codes":[],"extra":{"x":1}}`
	action, min := "login", 0.5
	out, _ := verifyWith(t, body, VerifyOptions{ExpectedHostname: "shop.example", ExpectedAction: &action, MinScore: &min})
	r := out.Result
	if !out.OK || out.Reason != "" || !r.Verified || *r.Score != 0.9 || *r.Hostname != "shop.example" || r.APKPackageName != nil || len(r.Reasons) != 1 || r.ErrorCodes == nil {
		t.Fatalf("%+v", out)
	}
}

func TestStrictResponseReading(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate success: the last wins, false": `{"success":true,"success":false,"hostname":"shop.example"}`,
		"case-folded key":                         `{"Success":true,"hostname":"shop.example"}`,
		"trailing data":                           `{"success":true,"hostname":"shop.example"} x`,
		"two objects":                             `{"success":true,"hostname":"shop.example"}{}`,
		"NaN":                                     `{"success":true,"hostname":"shop.example","score":NaN}`,
		"huge score":                              `{"success":true,"hostname":"shop.example","score":1e999}`,
		"huge negative exponent score is fine":    `{"success":true,"hostname":"shop.example","score":1e-999}`,
		"deep nesting":                            `{"success":true,"hostname":"shop.example","x":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`,
		"null known field":                        `{"success":true,"hostname":"shop.example","action":null}`,
		"string score":                            `{"success":true,"hostname":"shop.example","score":"0.9"}`,
		"bad challenge_ts":                        `{"success":true,"hostname":"shop.example","challenge_ts":"2026-02-30T00:00:00Z"}`,
		"unicode digits in challenge_ts":          `{"success":true,"hostname":"shop.example","challenge_ts":"٢٠٢٦-11-01T12:00:00Z"}`,
	} {
		out, _ := verifyWith(t, body, VerifyOptions{ExpectedHostname: "shop.example"})
		wantOK := name == "huge negative exponent score is fine"
		if wantOK {
			// A score of 1e-999 is a valid 0, but the check needs a threshold.
			if out.Reason != "threshold-missing" {
				t.Errorf("%s: %+v", name, out)
			}
			continue
		}
		if out.OK || out.Reason != "not-verified" {
			t.Errorf("%s: %+v", name, out)
		}
	}
}

func TestNeverPanics(t *testing.T) {
	var zero Client
	if out := zero.Verify(context.Background(), "abc", VerifyOptions{}); out.OK {
		t.Fatal("zero client passed")
	}
	var nilClient *Client
	if out := nilClient.Verify(context.Background(), "abc", VerifyOptions{}); out.OK {
		t.Fatal("nil client passed")
	}
	// A nil context is treated as Background; a RoundTripper that panics is a network error.
	s := &stub{handler: func(*http.Request) (*http.Response, error) { panic("boom") }}
	var nilCtx context.Context
	out := stubClient(t, s).Verify(nilCtx, "abc", VerifyOptions{ExpectedHostname: "shop.example"})
	if out.OK || out.Reason != "network-error" {
		t.Fatalf("%+v", out)
	}
}

func TestACancelledContextIsANetworkError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &stub{handler: respond(200, `{"success":true,"hostname":"shop.example"}`)}
	out := stubClient(t, s).Verify(ctx, "abc", VerifyOptions{ExpectedHostname: "shop.example"})
	if out.OK || out.Reason != "network-error" {
		t.Fatalf("%+v", out)
	}
}

func TestAnIPv4MappedAndMixedCaseRemoteIPIsSentAsGiven(t *testing.T) {
	for _, ipText := range []string{"::ffff:192.0.2.1", "2001:DB8::1"} {
		s := &stub{handler: respond(200, `{"success":true,"hostname":"shop.example"}`)}
		out := stubClient(t, s).Verify(context.Background(), "abc", VerifyOptions{ExpectedHostname: "shop.example", RemoteIP: ipText})
		form, _ := url.ParseQuery(s.bodies[0])
		if !out.OK || form.Get("remoteip") != ipText {
			t.Fatalf("%q: %+v %v", ipText, out, form)
		}
	}
}
