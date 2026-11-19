package revokegpt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ZaeemSattar/revokegpt-go/internal/jsonx"
	"github.com/ZaeemSattar/revokegpt-go/internal/schema"
)

const aidFixture = "aB3_-aB3_-aB3_-aB3_-aB3_-aB3_-aB3_-aB3_-cD"

var schemaNames = []string{"UserInfo", "AccountVerificationRequest", "AnnotateRequest", "EraseRequest", "AssessmentResponse", "aid"}

// schemaCases are the sdk-schemas cases of this task, with their values read as strict JSON (numbers kept as
// text, so a huge one is a json.Number and not a float).
func schemaCases(t *testing.T) []vectorCase {
	t.Helper()
	var out []vectorCase
	for _, c := range loadVector(t, "sdk-schemas.json").Cases {
		name, _ := obj(c["input"])["schema"].(string)
		for _, n := range schemaNames {
			if n == name {
				out = append(out, c)
			}
		}
	}
	return out
}

// strictValue re-reads a value of a loaded vector as strict JSON (json.Number).
func strictValue(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jsonx.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func judge(name string, v any) bool {
	switch name {
	case "UserInfo":
		return schema.UserInfo(v)
	case "AccountVerificationRequest":
		return schema.AccountVerification(v)
	case "AnnotateRequest":
		return schema.Annotate(v)
	case "EraseRequest":
		return schema.Erase(v)
	case "AssessmentResponse":
		return schema.Assessment(v)
	}
	s, ok := v.(string)
	if !ok {
		return false
	}
	_, ok = schema.AID(s)
	return ok
}

func TestSchemaValidatorsAlone(t *testing.T) {
	cases := schemaCases(t)
	for _, c := range cases {
		in := obj(c["input"])
		name := in["schema"].(string)
		want := obj(c["expected"])["valid"] == true
		t.Run(name+"/"+c["name"].(string), func(t *testing.T) {
			if got := judge(name, strictValue(t, in["value"])); got != want {
				t.Fatalf("valid = %v, want %v", got, want)
			}
		})
	}
	if len(cases) != 81+38+48+20+70+29 {
		t.Fatalf("%d cases", len(cases))
	}
}

// normTimes rewrites every RFC 3339 date-time string of a JSON value in the SDK's own spelling, so a value the
// SDK has re-formatted compares equal to the one given.
func normTimes(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = normTimes(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normTimes(e)
		}
		return out
	case string:
		if schema.DateTime(x) {
			if t, err := time.Parse(time.RFC3339Nano, x); err == nil {
				return rfc3339(t)
			}
		}
	case json.Number:
		f, _ := x.Float64()
		return f
	}
	return v
}

func decodeStrictInto(value any, into any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

// TestSchemasThroughTheCalls runs each request case through the public call. A value the typed request cannot
// hold (a null, an unknown key, a value of another type, an empty string where Go's "" is "absent") is not a
// call that can be written: it must be a value the schema refuses, or it is counted as not expressible, which
// is the Go language note of protocol v1 section 22.1a.
func TestSchemasThroughTheCalls(t *testing.T) {
	notExpressible, ran := 0, 0
	for _, c := range schemaCases(t) {
		in := obj(c["input"])
		name := in["schema"].(string)
		valid := obj(c["expected"])["valid"] == true
		value := strictValue(t, in["value"])
		t.Run(name+"/"+c["name"].(string), func(t *testing.T) {
			s := &stub{handler: respond(200, okAssessment)}
			client := stubClient(t, s)
			ctx := context.Background()
			var sent any
			var err error
			expressible := true
			switch name {
			case "UserInfo":
				var u UserInfo
				if expressible = decodeStrictInto(value, &u) == nil && sameValue(u.wire(), value); expressible {
					_, err = client.CreateAssessment(ctx, AssessmentInput{Token: "tok", UserInfo: &u})
					sent = bodyPath(s, "event", "userInfo")
				}
			case "AccountVerificationRequest":
				var a AccountVerification
				if expressible = decodeStrictInto(value, &a) == nil && sameValue(a.wire(), value); expressible {
					_, err = client.CreateAssessment(ctx, AssessmentInput{Token: "tok", UserInfo: &UserInfo{AccountRef: AccountRef{AccountID: "u"}}, AccountVerification: &a})
					sent = bodyPath(s, "accountVerification")
				}
			case "AnnotateRequest":
				var a AnnotateInput
				if expressible = decodeStrictInto(value, &a) == nil && sameValue(a.wire(), value); expressible {
					err = client.Annotate(ctx, aidFixture, a)
					sent = bodyPath(s)
				}
			case "EraseRequest":
				var r AccountRef
				if expressible = decodeStrictInto(value, &r) == nil && sameValue(refWire(r), value); expressible {
					err = client.EraseAccount(ctx, r)
					sent = bodyPath(s)
				}
			case "AssessmentResponse":
				s.handler = respond(200, mustJSON(value))
				var a *Assessment
				a, err = client.CreateAssessment(ctx, AssessmentInput{Token: "tok"})
				if valid {
					if err != nil || a == nil || !reflect.DeepEqual(normTimes(parseJSON(t, a.Raw)), normTimes(value)) {
						t.Fatalf("a valid response: %v", err)
					}
				} else if e := asError(err); e == nil || e.Code != "invalid-response" || e.Status != 200 {
					t.Fatalf("an invalid response: %v", err)
				}
				return
			case "aid":
				id, isString := value.(string)
				expressible = isString
				if expressible {
					err = client.Annotate(ctx, id, AnnotateInput{})
				}
			}
			if !expressible {
				if valid {
					t.Fatal("a valid value the typed request cannot hold")
				}
				if s.calls() != 0 {
					t.Fatal("sent")
				}
				notExpressible++
				return
			}
			ran++
			if !valid {
				if !isInputError(err) || s.calls() != 0 {
					t.Fatalf("want an argument error and no request, got %v (%d calls)", err, s.calls())
				}
				return
			}
			if err != nil || s.calls() != 1 {
				t.Fatalf("err %v calls %d", err, s.calls())
			}
			if name == "aid" {
				bare := strings.TrimPrefix(value.(string), "assessments/")
				if want := "/v1/assessments/" + bare + ":annotate"; s.reqs[0].URL.Path != want {
					t.Fatalf("path %q", s.reqs[0].URL.Path)
				}
				return
			}
			if !reflect.DeepEqual(normTimes(sent), normTimes(value)) {
				t.Fatalf("sent %v, want %v", sent, value)
			}
		})
	}
	t.Logf("%d cases through the call, %d not expressible in Go", ran, notExpressible)
	if ran != 145 || notExpressible != 71 {
		t.Fatalf("%d cases ran and %d were not expressible; the counts are pinned in protocol v1 section 22.1a", ran, notExpressible)
	}
}

const okAssessment = `{"name":"assessments/` + aidFixture + `","riskAnalysis":{"score":0.9,"reasons":[]},"tokenProperties":{"valid":true,"createTime":"2026-11-08T10:00:00Z","hostname":"shop.example"},"event":{"express":false}}`

func refWire(r AccountRef) wireObj {
	m := wireObj{}
	r.put(m)
	return m
}

func sameValue(w wireObj, value any) bool {
	return reflect.DeepEqual(normTimes(strictValue2(w)), normTimes(value))
}

func strictValue2(v any) any {
	b, _ := json.Marshal(v)
	out, _ := jsonx.Parse(b)
	return out
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func parseJSON(t *testing.T, b []byte) any {
	t.Helper()
	v, err := jsonx.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// bodyPath is the value at path of the JSON body of the last request.
func bodyPath(s *stub, path ...string) any {
	if s.calls() == 0 {
		return nil
	}
	v, err := jsonx.Parse([]byte(s.bodies[len(s.bodies)-1]))
	if err != nil {
		return nil
	}
	for _, k := range path {
		m, _ := v.(map[string]any)
		v = m[k]
	}
	return v
}

func asError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

func isInputError(err error) bool {
	var e *InputError
	return errors.As(err, &e) && errors.Is(err, ErrInvalidInput)
}
