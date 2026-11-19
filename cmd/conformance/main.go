//go:build conformance

// Command conformance is the runner program of the shared SDK conformance run (protocol v1 section 22.3). It
// reads one JSON object per line on stdin and writes one result line on stdout. It is a main package, so no
// program can import it, and it uses only the public API of the SDK. Run it from sdks/go with
// `go run -tags conformance ./cmd/conformance`; tools/sdk-conformance does. The tag keeps it out of
// `go build ./...` and `go install`, so no published artifact carries it.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	revokegpt "github.com/ZaeemSattar/revokegpt-go"
)

type obj = map[string]any

const maxLine = 16 << 20

func main() {
	os.Exit(serve(os.Stdin, os.Stdout))
}

func serve(in io.Reader, out io.Writer) int {
	r := bufio.NewReaderSize(in, 1<<20)
	w := bufio.NewWriter(out)
	for {
		raw, err := readLine(r)
		if len(raw) > 0 && len(trim(raw)) > 0 {
			name, answer, perr := handle(raw)
			if perr != nil {
				// Never echo the message: it could carry request data.
				writeLine(w, obj{"name": name, "fatal": "bad input line"})
				return 1
			}
			writeLine(w, answer)
		}
		if err != nil {
			return 0
		}
	}
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		line = append(line, chunk...)
		if len(line) > maxLine {
			return nil, io.ErrShortBuffer
		}
		if err != nil || !isPrefix {
			return line, err
		}
	}
}

func trim(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r') {
		b = b[1:]
	}
	return b
}

func writeLine(w *bufio.Writer, v obj) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"fatal":"unencodable answer"}`)
	}
	_, _ = w.Write(append(b, '\n'))
	_ = w.Flush()
}

func handle(raw []byte) (name string, answer obj, err error) {
	var line struct {
		Case     obj    `json:"case"`
		Endpoint string `json:"endpoint"`
		Secret   string `json:"secret"`
		Mode     string `json:"mode"`
		Live     bool   `json:"live"`
		SiteKey  string `json:"siteKey"`
	}
	if err := json.Unmarshal(raw, &line); err != nil {
		return "", nil, err
	}
	name, _ = line.Case["name"].(string)
	if name == "" {
		return "", nil, fmt.Errorf("no case name")
	}
	var res obj
	switch {
	case line.Live:
		res = runLive(line.Endpoint, line.Secret, line.SiteKey)(line.Case)
	case line.Mode == "async":
		// Go has no async surface: every call takes a context.
		res = obj{"unsupported": "async"}
	default:
		res = call(line.Case, line.Endpoint, line.Secret)
	}
	res["name"] = name
	return name, res, nil
}

// runLive is the live entry point (protocol v1 section 22.3): runLive(endpoint, secret, siteKey)(case) answers
// one case against a real endpoint. A case that needs a site key and has none of its own gets siteKey.
func runLive(endpoint, secret, siteKey string) func(obj) obj {
	return func(c obj) obj {
		if siteKey != "" {
			if args, ok := c["args"].(obj); ok {
				if opts, ok := args["options"].(obj); ok {
					if _, has := opts["sitekey"]; !has {
						opts["sitekey"] = siteKey
					}
				}
			}
		}
		return call(c, endpoint, secret)
	}
}

// hasNull reports whether a JSON value holds a null anywhere. Go has no null for a plain field, so a case that
// carries one is not run: "given but null" cannot be told from "absent" in the typed request (protocol v1
// section 22.1a), and answering `unsupported` makes the driver count it instead of passing it for the wrong
// reason.
func hasNull(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case obj:
		for _, e := range x {
			if hasNull(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if hasNull(e) {
				return true
			}
		}
	}
	return false
}

// timeout maps timeoutMs to a WithTimeout option. A value that is not a whole number of milliseconds is an
// argument error, as in the reference; ok is false then.
func timeout(args obj) (opts []revokegpt.Option, inputErr bool) {
	v, present := args["timeoutMs"]
	if !present {
		return nil, false
	}
	ms, isNum := v.(float64)
	if !isNum || ms != math.Trunc(ms) || ms < 1 || ms > 60000 {
		return nil, true
	}
	return []revokegpt.Option{revokegpt.WithTimeout(time.Duration(ms) * time.Millisecond)}, false
}

func call(c obj, endpoint, secret string) obj {
	name, _ := c["call"].(string)
	args, _ := c["args"].(obj)
	switch name {
	case "verify", "createAssessment", "annotate", "eraseAccount", "cardFields":
	default:
		return obj{"unsupported": name}
	}
	if hasNull(args) {
		return obj{"unsupported": "null"}
	}
	if name == "cardFields" {
		return callCardFields(args)
	}
	opts, bad := timeout(args)
	if bad {
		return obj{"inputError": true}
	}
	client, err := revokegpt.New(secret, endpoint, opts...)
	if err != nil {
		return obj{"inputError": true}
	}
	ctx := context.Background()
	if name == "verify" {
		return callVerify(ctx, client, args)
	}
	input, _ := args["input"].(obj)
	switch name {
	case "createAssessment":
		var in revokegpt.AssessmentInput
		if !decode(input, &in) {
			return obj{"inputError": true}
		}
		a, err := client.CreateAssessment(ctx, in)
		if err != nil {
			return failure(err)
		}
		var raw any
		if json.Unmarshal(a.Raw, &raw) != nil {
			return obj{"fatal": "unreadable result"}
		}
		return obj{"result": raw}
	case "annotate":
		var in revokegpt.AnnotateInput
		aid, _ := args["aid"].(string)
		if !decode(input, &in) {
			return obj{"inputError": true}
		}
		return done(client.Annotate(ctx, aid, in))
	default:
		var ref revokegpt.AccountRef
		if !decode(input, &ref) {
			return obj{"inputError": true}
		}
		return done(client.EraseAccount(ctx, ref))
	}
}

// decode reads a wire-neutral input into a request type. An unknown key or a value of the wrong type is an
// argument error, so the answer is inputError.
func decode(m obj, into any) bool {
	if m == nil {
		return true
	}
	b, err := json.Marshal(m)
	if err != nil {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(into) == nil
}

// callCardFields answers the helper that makes no request.
func callCardFields(args obj) obj {
	bin, ok1 := optString(args, "bin")
	last4, ok2 := optString(args, "last4")
	if !ok1 || !ok2 {
		return obj{"inputError": true}
	}
	card, err := revokegpt.CardFields(bin, last4)
	if err != nil {
		return failure(err)
	}
	result := obj{}
	if card.BIN != "" {
		result["cardBin"] = card.BIN
	}
	if card.Last4 != "" {
		result["cardLastFour"] = card.Last4
	}
	return obj{"result": result}
}

// optString reads an optional string argument; ok is false for another type.
func optString(args obj, key string) (string, bool) {
	v, present := args[key]
	if !present {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}

func done(err error) obj {
	if err != nil {
		return failure(err)
	}
	return obj{"result": nil}
}

// failure maps a call's error: an *Error, or an argument error.
func failure(err error) obj {
	var e *revokegpt.Error
	if errors.As(err, &e) {
		out := obj{"code": e.Code, "status": e.Status, "unavailable": revokegpt.IsUnavailable(err)}
		if e.RequestID != "" {
			out["requestId"] = e.RequestID
		}
		if e.RetryAfterSeconds != nil {
			out["retryAfterSeconds"] = *e.RetryAfterSeconds
		}
		return obj{"error": out}
	}
	if errors.Is(err, revokegpt.ErrInvalidInput) {
		return obj{"inputError": true}
	}
	return obj{"fatal": "unexpected error type"}
}

func callVerify(ctx context.Context, client *revokegpt.Client, args obj) obj {
	token, ok := args["token"].(string)
	vo, ok2 := verifyOptions(args["options"])
	if !ok || !ok2 {
		return obj{"unsupported": "argument type"}
	}
	o := client.Verify(ctx, token, vo)
	outcome := obj{"ok": o.OK, "result": resultJSON(o.Result)}
	if o.Reason != "" {
		outcome["reason"] = o.Reason
	}
	return obj{"outcome": outcome}
}

// verifyOptions maps the wire-neutral options of a case. An unknown key or a value of the wrong type reports
// false (a null never gets here: call answers `unsupported` first).
func verifyOptions(v any) (revokegpt.VerifyOptions, bool) {
	var o revokegpt.VerifyOptions
	m, _ := v.(obj)
	for key, val := range m {
		var ok bool
		switch key {
		case "expectedHostname":
			o.ExpectedHostname, ok = val.(string)
		case "remoteip":
			o.RemoteIP, ok = val.(string)
		case "sitekey":
			o.SiteKey, ok = val.(string)
		case "expectedAction":
			var s string
			if s, ok = val.(string); ok {
				o.ExpectedAction = &s
			}
		case "minScore":
			var f float64
			if f, ok = val.(float64); ok {
				o.MinScore = &f
			}
		case "expectedApp":
			var app obj
			if app, ok = val.(obj); ok {
				p, _ := app["platform"].(string)
				id, _ := app["id"].(string)
				o.ExpectedApp = &revokegpt.ExpectedApp{Platform: p, ID: id}
			}
		}
		if !ok {
			return o, false
		}
	}
	return o, true
}

func resultJSON(r revokegpt.SiteverifyResult) obj {
	return obj{
		"verified":       r.Verified,
		"score":          r.Score,
		"action":         r.Action,
		"hostname":       r.Hostname,
		"errorCodes":     r.ErrorCodes,
		"reasons":        r.Reasons,
		"apkPackageName": r.APKPackageName,
		"iosBundleId":    r.IOSBundleID,
	}
}
