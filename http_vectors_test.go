package revokegpt

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ZaeemSattar/revokegpt-go/internal/jsonx"
)

// subset reports whether every field named in want equals the field of got (objects recursively, lists
// element by element, scalars exactly).
func subset(want, got any) bool {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range w {
			if !subset(v, g[k]) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !subset(w[i], g[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(normTimes(want), normTimes(got))
}

func decodeInput(m map[string]any, into any) error {
	if m == nil {
		return nil
	}
	return decodeStrictInto(m, into)
}

func TestSDKHTTPAssessmentCases(t *testing.T) {
	secret := fixtureSecret(t)
	ran := 0
	for _, c := range loadVector(t, "sdk-http.json").Cases {
		call, _ := c["call"].(string)
		if call != "createAssessment" && call != "annotate" && call != "eraseAccount" {
			continue
		}
		name := c["name"].(string)
		t.Run(name, func(t *testing.T) {
			ran++
			args, ex := obj(c["args"]), obj(c["expected"])
			s := &stub{handler: scripted(t, obj(c["response"]))}
			var opts []Option
			if ms, ok := args["timeoutMs"].(float64); ok {
				opts = append(opts, WithTimeout(time.Duration(ms)*time.Millisecond))
			}
			client := stubClient(t, s, opts...)
			ctx := context.Background()
			input := obj(args["input"])
			var result any
			var err error
			switch call {
			case "createAssessment":
				var in AssessmentInput
				if err = decodeInput(input, &in); err != nil {
					err = inputError("decode")
					break
				}
				var a *Assessment
				if a, err = client.CreateAssessment(ctx, in); err == nil {
					result = parseJSON(t, a.Raw)
				}
			case "annotate":
				var in AnnotateInput
				if err = decodeInput(input, &in); err != nil {
					err = inputError("decode")
					break
				}
				err = client.Annotate(ctx, args["aid"].(string), in)
			default:
				var ref AccountRef
				if err = decodeInput(input, &ref); err != nil {
					err = inputError("decode")
					break
				}
				err = client.EraseAccount(ctx, ref)
			}
			checkRequest(t, s, obj(ex["request"]), secret)
			switch {
			case ex["inputError"] == true:
				if !isInputError(err) {
					t.Fatalf("want an argument error, got %v", err)
				}
			case ex["error"] != nil:
				want := obj(ex["error"])
				e := asError(err)
				if e == nil {
					t.Fatalf("want an *Error, got %v", err)
				}
				checkError(t, e, err, want)
			default:
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				if want, has := ex["result"]; has && want != nil && !subset(strictValue(t, want), result) {
					t.Fatalf("result %v, want %v", result, want)
				}
				if has := ex["result"] == nil; has && result != nil {
					t.Fatalf("a call that returns nothing returned %v", result)
				}
			}
		})
	}
	if ran != 46+20+8 {
		t.Fatalf("ran %d", ran)
	}
}

func checkError(t *testing.T, e *Error, err error, want map[string]any) {
	t.Helper()
	if e.Code != want["code"] || float64(e.Status) != want["status"] {
		t.Fatalf("error %q/%d, want %v/%v", e.Code, e.Status, want["code"], want["status"])
	}
	if id, has := want["requestId"].(string); has != (e.RequestID != "") || (has && e.RequestID != id) {
		t.Fatalf("request id %q, want %v", e.RequestID, want["requestId"])
	}
	secs, has := want["retryAfterSeconds"].(float64)
	if has != (e.RetryAfterSeconds != nil) || (has && float64(*e.RetryAfterSeconds) != secs) {
		t.Fatalf("retry after %v, want %v", e.RetryAfterSeconds, want["retryAfterSeconds"])
	}
	if IsUnavailable(err) != (want["unavailable"] == true) {
		t.Fatalf("IsUnavailable = %v", IsUnavailable(err))
	}
}

func checkRequest(t *testing.T, s *stub, req map[string]any, secret string) {
	t.Helper()
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
	if got := r.Header.Get("Authorization"); got != "Bearer "+secret {
		t.Fatalf("authorization %q", got)
	}
	// The secret is in that header and nowhere else.
	if strings.Contains(r.URL.String(), "rgsk_") || strings.Contains(s.bodies[0], secret) || r.URL.RawQuery != "" {
		t.Fatal("the secret is outside the Authorization header")
	}
	if want, has := req["json"]; has {
		got, err := jsonx.Parse([]byte(s.bodies[0]))
		if err != nil || !reflect.DeepEqual(normTimes(got), normTimes(strictValue(t, want))) {
			t.Fatalf("json %s, want %v", s.bodies[0], want)
		}
	}
	if want, has := req["jsonSubset"]; has {
		got, _ := jsonx.Parse([]byte(s.bodies[0]))
		if !subset(strictValue(t, want), got) {
			t.Fatalf("json %s, want a superset of %v", s.bodies[0], want)
		}
	}
}
