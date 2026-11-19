package revokegpt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ZaeemSattar/revokegpt-go/internal/jsonx"
	"github.com/ZaeemSattar/revokegpt-go/internal/schema"
)

const siteverifySuffix = "/siteverify"

// v1Root is the .../v1 root of the endpoint. The calls other than Verify derive their URLs from it, so the
// endpoint must end in /siteverify.
func (c *Client) v1Root() (string, error) {
	if c == nil || c.c == nil {
		return "", inputError("client: create it with New")
	}
	if !strings.HasSuffix(c.c.endpoint, siteverifySuffix) {
		return "", inputError("endpoint: this call needs an endpoint that ends in /siteverify")
	}
	return strings.TrimSuffix(c.c.endpoint, siteverifySuffix), nil
}

// post sends a JSON body with the secret as a Bearer and reads the answer as JSON: the parsed value and the
// body, or an *Error.
func (c *Client) post(ctx context.Context, url string, wire any) (any, []byte, error) {
	raw, err := c.postRaw(ctx, url, wire, "application/json", maxResponseBytes)
	if err != nil {
		return nil, nil, err
	}
	return readJSON(raw)
}

// postRaw sends a JSON body with the secret as a Bearer and returns the answer as read (the body of any status
// but a redirect, through the cap). An *InputError means nothing was sent; any *Error is a failed exchange.
func (c *Client) postRaw(ctx context.Context, url string, wire any, accept string, limit int64) (*rawResponse, error) {
	if !validWire(wire) {
		return nil, inputError("request: not encodable")
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return nil, inputError("request: not encodable")
	}
	raw, err := c.c.do(ctx, request{
		url: url, contentType: "application/json", body: body, bearer: string(c.c.secret), accept: accept, errorBody: true, limit: limit,
	})
	if err != nil {
		// A cancelled or expired context (the caller's, or this client's timeout) is matchable with errors.Is. The
		// transport's own error is never wrapped: it could carry the request.
		e := &Error{Code: "network-error"}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			e.cause = err
		}
		return nil, e
	}
	return raw, nil
}

// validWire is true for a request that json.Marshal can encode without surprises: it refuses a NaN or an
// infinity (an error) and a string that is not valid UTF-8 (rewritten to U+FFFD, so the service would see a
// different value). The schema checks run first for the fields they cover; this guards the free-text ones
// (token, action, address, user agent, headers).
func validWire(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			if !validWire(e) {
				return false
			}
		}
	case []any:
		for _, e := range x {
			if !validWire(e) {
				return false
			}
		}
	case string:
		return utf8.ValidString(x)
	case bool, int, int64:
	case float64:
		return x == x && x-x == 0
	default:
		return false
	}
	return true
}

// retryAfter is 1 to 6 ASCII digits of seconds; anything else (a date, a sign, a fraction, more digits) is nil.
func retryAfter(h http.Header) *int {
	v := strings.Join(h.Values("Retry-After"), ", ")
	if len(v) < 1 || len(v) > 6 {
		return nil
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return nil
		}
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return nil
	}
	return &n
}

// readJSON turns an answer into the parsed JSON of a 200, or an *Error: the code and request id of an error
// body when it has them, internal-error otherwise, and invalid-response for a 200 that is not JSON, is too
// large, or is another 2xx status. HTTP 503 is always service-unavailable (see IsUnavailable).
func readJSON(raw *rawResponse) (any, []byte, error) {
	status := raw.Status
	var parsed any
	var ok bool
	if raw.Body != nil && !raw.TooLarge {
		var err error
		if parsed, err = jsonx.Parse(raw.Body); err == nil {
			ok = true
		}
	}
	if status < 200 || status > 299 {
		e := &Error{Code: "internal-error", Status: status, RetryAfterSeconds: retryAfter(raw.Header)}
		if m, isObj := parsed.(map[string]any); ok && isObj {
			if body, isObj := m["error"].(map[string]any); isObj {
				if code, isStr := body["code"].(string); isStr {
					e.Code = code
				}
				if id, isStr := body["requestId"].(string); isStr {
					e.RequestID = id
				}
			}
		}
		if status == http.StatusServiceUnavailable {
			e.Code = "service-unavailable"
		}
		return nil, nil, e
	}
	if status != http.StatusOK || !ok {
		return nil, nil, &Error{Code: "invalid-response", Status: status}
	}
	return parsed, raw.Body, nil
}

// CreateAssessment scores a response token (or, with Express, an IP address alone) and returns the Assessment.
//
// It needs an endpoint that ends in /siteverify (an *InputError otherwise). A bad request is an *InputError
// before anything is sent; a failed call is an *Error (errors.As), and IsUnavailable tells the 503 case. A
// token is single use, so this never retries.
func (c *Client) CreateAssessment(ctx context.Context, in AssessmentInput) (*Assessment, error) {
	root, err := c.v1Root()
	if err != nil {
		return nil, err
	}
	event := wireObj{}
	put(event, "token", in.Token)
	put(event, "expectedAction", in.ExpectedAction)
	if in.Express {
		event["express"] = true
	}
	put(event, "userIpAddress", in.UserIPAddress)
	put(event, "userAgent", in.UserAgent)
	putStrings(event, "headers", in.Headers)
	if in.FraudPrevention != "" {
		if !schema.FraudPrevention(in.FraudPrevention) {
			return nil, inputError("fraud prevention")
		}
		event["fraudPrevention"] = in.FraudPrevention
	}
	request := wireObj{"event": event}
	if in.UserInfo != nil {
		w := in.UserInfo.wire()
		if !schema.UserInfo(w) {
			return nil, inputError("user info")
		}
		event["userInfo"] = w
	}
	if in.TransactionData != nil {
		w := in.TransactionData.wire()
		if err := scanTransactionData(w); err != nil { // a card number is refused before anything else is judged
			return nil, err
		}
		if !schema.TransactionData(w) {
			return nil, inputError("transaction data")
		}
		event["transactionData"] = w
	}
	if in.AccountVerification != nil {
		info, _ := event["userInfo"].(wireObj)
		_, named := info["accountId"]
		_, hashed := info["hashedAccountId"]
		if !named && !hashed {
			return nil, inputError("account verification: needs a named account in user info")
		}
		w := in.AccountVerification.wire()
		if !schema.AccountVerification(w) {
			return nil, inputError("account verification")
		}
		request["accountVerification"] = w
	}
	parsed, body, err := c.post(ctx, root+"/assessments", request)
	if err != nil {
		return nil, err
	}
	if !schema.Assessment(parsed) {
		return nil, &Error{Code: "invalid-response", Status: http.StatusOK}
	}
	return newAssessment(parsed.(map[string]any), body), nil
}

// Annotate reports what happened after an assessment: an annotation (LEGITIMATE or FRAUDULENT), reasons, the
// account a password or two-factor outcome belongs to, or the outcome of a payment. nameOrAID is the
// assessment's name (assessments/<id>) or its bare id. An empty AnnotateInput is sent, and the service refuses
// it (bad-request).
func (c *Client) Annotate(ctx context.Context, nameOrAID string, in AnnotateInput) error {
	root, err := c.v1Root()
	if err != nil {
		return err
	}
	aid, ok := schema.AID(nameOrAID)
	if !ok {
		return inputError("assessment id")
	}
	w := in.wire()
	if ev, ok := w["transactionEvent"].(wireObj); ok && hasPAN(ev["reason"]) {
		return &Error{Code: errCardNumber.Code}
	}
	if !schema.Annotate(w) {
		return inputError("annotate input")
	}
	_, _, err = c.post(ctx, root+"/assessments/"+aid+":annotate", w)
	return err
}

// EraseAccount erases what the service holds for an account: name it with exactly one of AccountID and
// HashedAccountID, the same form you used when you assessed it.
func (c *Client) EraseAccount(ctx context.Context, ref AccountRef) error {
	root, err := c.v1Root()
	if err != nil {
		return err
	}
	w := wireObj{}
	ref.put(w)
	if !schema.Erase(w) {
		return inputError("account reference")
	}
	_, _, err = c.post(ctx, root+"/accounts:erase", w)
	return err
}
