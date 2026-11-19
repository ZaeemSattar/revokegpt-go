package revokegpt

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"testing"

	"github.com/ZaeemSattar/revokegpt-go/hostname"
	"github.com/ZaeemSattar/revokegpt-go/internal/ip"
	"github.com/ZaeemSattar/revokegpt-go/internal/keys"
)

const vectorToken = "vector-token_0123456789"

// conservativeHostnames are the hostnames.json cases whose reference result needs the full UTS 46 mapping or newer
// Unicode tables. The lifted reader refuses them (it fails closed, the same as the M9 firewall port). Through
// Verify only the last one is observable: its input is already the canonical form, so the reference accepts it
// as an expectation (protocol v1 section 22.1a).
var conservativeHostnames = map[string]bool{
	"canonical: ideographic full stop is a dot":                                                 true,
	"canonical: full-width letter folds to ASCII":                                               true,
	"canonical: soft hyphen (U+00AD) is ignored":                                                true,
	"canonical: zero-width space (U+200B) is ignored":                                           true,
	"canonical: runtime-normative (workerd/ada; Chrome, Bun and Deno reject): U+10D42 label":    true,
	"canonical: runtime-normative (workerd/ada; Chrome, Bun and Deno reject): xn--6ud3120f38uc": true,
	"canonical: runtime-normative (workerd/ada; Deno rejects): U+10D72 label":                   true,
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func verifyWith(t *testing.T, body string, o VerifyOptions) (VerifyOutcome, *stub) {
	t.Helper()
	s := &stub{handler: respond(200, body)}
	return stubClient(t, s).Verify(context.Background(), vectorToken, o), s
}

func runKeys(t *testing.T, c vectorCase) {
	in, ex := obj(c["input"]), obj(c["expected"])
	if sk, ok := in["siteKey"].(string); ok {
		if keys.IsSiteKey(sk) != (ex["valid"] == true) {
			t.Fatal("site key")
		}
		return
	}
	key, isString := in["key"].(string)
	kind, id, ok := keys.ParseSecret(key)
	if ok != (isString && ex["valid"] == true) {
		t.Fatalf("valid = %v, want %v", ok, ex["valid"])
	}
	if ok && (string(kind) != ex["kind"] || id != ex["keyId"]) {
		t.Fatalf("kind %q id %q", kind, id)
	}
	// New accepts exactly the secret keys that parse as secret keys.
	_, err := New(key, testEndpoint)
	if (err == nil) != (ok && kind == keys.Secret) {
		t.Fatalf("New: %v", err)
	}
}

func runHostnames(t *testing.T, c vectorCase) {
	host, _ := obj(c["input"])["host"].(string)
	want, wantOK := obj(c["expected"])["canonical"].(string)
	got, ok := hostname.Canonicalize(host)
	if conservativeHostnames[c["name"].(string)] {
		if ok {
			t.Fatalf("a conservative case must be refused, got %q", got)
		}
		return
	}
	if ok != wantOK || got != want {
		t.Fatalf("Canonicalize(%q) = %q, %v; want %q, %v", host, got, ok, want, wantOK)
	}
	// Through Verify: only an already canonical hostname is a valid expectation.
	out, s := verifyWith(t, `{"success":true,"hostname":"x.example"}`, VerifyOptions{ExpectedHostname: host})
	if !wantOK || want != host {
		if out.OK || out.Reason != "invalid-expectation" || s.calls() != 0 {
			t.Fatalf("outcome %+v, calls %d", out, s.calls())
		}
	} else {
		// A canonical hostname is accepted: the request is sent and only the answer's hostname can fail it.
		if s.calls() != 1 || out.Reason != "hostname-mismatch" {
			t.Fatalf("outcome %+v, calls %d", out, s.calls())
		}
	}
}

func runFields(t *testing.T, c vectorCase) {
	in := obj(c["input"])
	value, isString := in["value"].(string)
	if in["field"] != "action" || !isString {
		return
	}
	// The action charset is the edge's rule. The SDK compares an action exactly and never rewrites it, so a value
	// the edge would refuse can never match one it issued.
	body, _ := json.Marshal(map[string]any{"success": true, "hostname": "shop.example", "action": value})
	out, _ := verifyWith(t, string(body), VerifyOptions{ExpectedHostname: "shop.example", ExpectedAction: &value})
	if !out.OK || out.Result.Action == nil || *out.Result.Action != value {
		t.Fatalf("outcome %+v", out)
	}
	other := value + "x"
	out, _ = verifyWith(t, string(body), VerifyOptions{ExpectedHostname: "shop.example", ExpectedAction: &other})
	if out.Reason != "action-mismatch" {
		t.Fatalf("reason %q", out.Reason)
	}
}

func jsonStrings(v any) []string {
	out := []string{}
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ptrEq[T comparable](p *T, v any) bool {
	if v == nil {
		return p == nil
	}
	w, ok := v.(T)
	return ok && p != nil && *p == w
}

func runSiteverify(t *testing.T, c vectorCase) {
	r, e := parseSiteverify([]byte(obj(c["input"])["body"].(string))), obj(c["expected"])
	if r.Verified != e["verified"] || !ptrEq(r.Score, e["score"]) || !ptrEq(r.Action, e["action"]) ||
		!ptrEq(r.Hostname, e["hostname"]) || !ptrEq(r.APKPackageName, e["apkPackageName"]) || !ptrEq(r.IOSBundleID, e["iosBundleId"]) ||
		!eqStrings(r.ErrorCodes, jsonStrings(e["errorCodes"])) || !eqStrings(r.Reasons, jsonStrings(e["reasons"])) {
		t.Fatalf("result %+v, want %v", r, e)
	}
}

// notExpressible reports whether an expectation holds a value Go's typed options cannot: a JSON null ("given, but
// invalid": Go's nil is the "absent" value, protocol v1 section 22.1a) or another type (a number for a hostname).
// A null app is fine: no app is the same as none given, and both are invalid-expectation.
func notExpressible(expect map[string]any) bool {
	if h, ok := expect["hostname"]; ok {
		if _, isString := h.(string); !isString {
			return true
		}
	}
	if a, ok := expect["action"]; ok {
		if _, isString := a.(string); !isString {
			return true
		}
	}
	if m, ok := expect["minScore"]; ok {
		if _, isNum := m.(float64); !isNum {
			return true
		}
	}
	if app, ok := expect["app"]; ok && app != nil {
		m, isObj := app.(map[string]any)
		if !isObj {
			return true
		}
		for _, k := range []string{"platform", "id"} {
			if v, has := m[k]; has {
				if _, isString := v.(string); !isString { // null included
					return true
				}
			}
		}
	}
	return false
}

func toOptions(expect map[string]any) VerifyOptions {
	var o VerifyOptions
	if h, ok := expect["hostname"].(string); ok {
		o.ExpectedHostname = h
	}
	if app, ok := expect["app"].(map[string]any); ok {
		p, _ := app["platform"].(string)
		id, _ := app["id"].(string)
		o.ExpectedApp = &ExpectedApp{Platform: p, ID: id}
	}
	if a, ok := expect["action"].(string); ok {
		o.ExpectedAction = &a
	}
	if m, ok := expect["minScore"].(float64); ok {
		o.MinScore = &m
	}
	return o
}

func runRelyingParty(t *testing.T, c vectorCase) {
	in := obj(c["input"])
	body, expect, ex := in["body"].(string), obj(in["expect"]), obj(c["expected"])
	reason, _ := ex["reason"].(string)
	if notExpressible(expect) {
		t.Skip("a JSON null (the absent value in Go) or a value of a type Go's options cannot hold")
	}
	out, s := verifyWith(t, body, toOptions(expect))
	if out.OK != (ex["ok"] == true) || out.Reason != reason {
		t.Fatalf("outcome %+v, want %v", out, ex)
	}
	if reason == "invalid-expectation" {
		if s.calls() != 0 { // refused before the token is sent (and spent)
			t.Fatal("a request was sent")
		}
		return
	}
	if s.calls() != 1 {
		t.Fatalf("calls %d", s.calls())
	}
	if want := parseSiteverify([]byte(body)); !equalResult(out.Result, want) {
		t.Fatalf("result %+v, want %+v", out.Result, want)
	}
}

func equalResult(a, b SiteverifyResult) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func runSchemas(t *testing.T, c vectorCase) {
	in, valid := obj(c["input"]), obj(c["expected"])["valid"] == true
	schema, value := in["schema"].(string), in["value"]
	str, isString := value.(string)
	if !isString {
		// A number or a null cannot be a Go string; the empty string is "not given" and is no case.
		t.Skip("not a string")
	}
	if schema == "remoteip" {
		if _, ok := ip.Canonical(str); ok != valid {
			t.Fatalf("canonical ip: %v", ok)
		}
		out, s := verifyWith(t, `{"success":true,"hostname":"shop.example"}`, VerifyOptions{ExpectedHostname: "shop.example", RemoteIP: str})
		checkSent(t, out, s, valid)
	} else {
		if keys.IsSiteKey(str) != valid {
			t.Fatal("site key")
		}
		out, s := verifyWith(t, `{"success":true,"hostname":"shop.example"}`, VerifyOptions{ExpectedHostname: "shop.example", SiteKey: str})
		checkSent(t, out, s, valid)
	}
}

func checkSent(t *testing.T, out VerifyOutcome, s *stub, valid bool) {
	t.Helper()
	if valid {
		if !out.OK || s.calls() != 1 {
			t.Fatalf("outcome %+v calls %d", out, s.calls())
		}
		if got := s.reqs[0].Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Fatal(got)
		}
		return
	}
	if out.OK || out.Reason != "invalid-options" || s.calls() != 0 {
		t.Fatalf("outcome %+v calls %d", out, s.calls())
	}
}

type handler func(*testing.T, vectorCase)

// handlers are the suites this task runs, by manifest file name.
var handlers = map[string]handler{
	"keys.json":          runKeys,
	"hostnames.json":     runHostnames,
	"fields.json":        runFields,
	"siteverify.json":    runSiteverify,
	"relying-party.json": runRelyingParty,
	"sdk-schemas.json":   runSchemas,
}

// later are the required suites that other test files run: pan-scan and transaction-data (payments_test.go),
// and sdk-http.json (verify_test.go and http_vectors_test.go).
var later = []string{"pan-scan.json", "transaction-data.json"}

// selectCase says which cases of a file a server SDK runs here: hashing with a pepper is edge logic, pattern and
// allowlist matching is the firewall's, and the other schemas of sdk-schemas.json belong to later tasks.
func selectCase(file string, c vectorCase) bool {
	in, ex := obj(c["input"]), obj(c["expected"])
	switch file {
	case "keys.json":
		_, pepper := in["pepperHex"]
		return !pepper
	case "hostnames.json":
		_, ok := ex["canonical"]
		return ok
	case "sdk-schemas.json":
		return in["schema"] == "remoteip" || in["schema"] == "siteKey"
	}
	return true
}

func TestRegistryMatchesTheManifest(t *testing.T) {
	var required []string
	for _, s := range loadVector(t, "sdk-conformance.json").Suites {
		if s.Server == "required" {
			required = append(required, s.File)
		}
	}
	have := []string{"sdk-http.json"}
	have = append(have, later...)
	for f := range handlers {
		have = append(have, f)
	}
	sort.Strings(required)
	sort.Strings(have)
	if !eqStrings(required, have) {
		t.Fatalf("required %v\nhandled  %v", required, have)
	}
}

func TestVectors(t *testing.T) {
	for file, run := range handlers {
		cases := 0
		for _, c := range loadVector(t, file).Cases {
			if !selectCase(file, c) {
				continue
			}
			cases++
			t.Run(file+"/"+c["name"].(string), func(t *testing.T) { run(t, c) })
		}
		if cases == 0 {
			t.Errorf("%s: no cases", file)
		}
	}
}

func TestTheCasesGoCannotExpressAreCounted(t *testing.T) {
	// 7 cases with a null or mistyped threshold, action or app id: the "given but invalid" cases of protocol v1
	// section 22.1a.
	n := 0
	for _, c := range loadVector(t, "relying-party.json").Cases {
		if notExpressible(obj(obj(c["input"])["expect"])) {
			n++
		}
	}
	if n != 7 {
		t.Fatalf("%d relying-party cases are not run through Verify, want 7", n)
	}
}

func TestNaNAndInfiniteThresholdsAreInvalid(t *testing.T) {
	for _, m := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -0.1, 1.1, 1e308, -1e308} {
		m := m
		out, s := verifyWith(t, `{"success":true,"hostname":"shop.example","score":0.9}`, VerifyOptions{ExpectedHostname: "shop.example", MinScore: &m})
		if out.OK || out.Reason != "invalid-expectation" || s.calls() != 0 {
			t.Fatalf("min score %v: %+v", m, out)
		}
	}
}
