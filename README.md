# revokegpt (Go)

The RevokeGPT server SDK for Go 1.26 or later. It sends a response token to siteverify and applies every
relying-party check of protocol v1 section 7: `success` must be the boolean `true`, the hostname (or app) must match
exactly, the action must match exactly, and a score must meet your threshold. It also wraps the assessment, account
protection, payment and erase calls. The core module uses the standard library only.

## Install

The module is not tagged yet. Until the first release, use a checkout of this repository: in your own module run

```sh
go mod edit -require github.com/ZaeemSattar/revokegpt-go@v0.0.0
go mod edit -replace github.com/ZaeemSattar/revokegpt-go=/path/to/checkout/sdks/go
```

After release it is `go get github.com/ZaeemSattar/revokegpt-go`. The firewall middleware is a second module
(`github.com/ZaeemSattar/revokegpt-go/firewall`, in `sdks/integrations/go` of this repository).

## Quickstart

```go
package main

import (
	"net"
	"net/http"
	"os"

	revokegpt "github.com/ZaeemSattar/revokegpt-go"
)

func main() {
	// Create the client once. The secret (rgsk_...) is checked here and never appears in fmt, slog, JSON or an error.
	client, err := revokegpt.New(os.Getenv("REVOKEGPT_SECRET"), "https://<api host>/v1/siteverify")
	if err != nil {
		panic(err) // an *InputError (errors.Is(err, revokegpt.ErrInvalidInput)); its text never includes the value
	}
	http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		token := r.PostFormValue("<the widget's response field>")
		ip, _, _ := net.SplitHostPort(r.RemoteAddr) // see "Trusted client IP"
		action, min := "signup", 0.5
		out := client.Verify(r.Context(), token, revokegpt.VerifyOptions{
			ExpectedHostname: "shop.example", // the hostname your page is served from, lowercase
			ExpectedAction:   &action,        // the action your page passed to the widget
			MinScore:         &min,           // required: every verified result carries a score
			RemoteIP:         ip,             // optional
		})
		if !out.OK {
			http.Error(w, "verification failed", http.StatusForbidden) // out.Reason says why; log it
			return
		}
		// ... create the account
	})
	_ = http.ListenAndServe(":8080", nil)
}
```

Gate on `out.OK` alone. `out.Result` is the parsed siteverify result (`Score`, `Action`, `Hostname`, `ErrorCodes`,
`Reasons`, ...), for logging. `Verify` never returns an error and never panics: every failure is an outcome.

### Trusted client IP

`RemoteIP` must be the real end user's address. Behind a proxy or load balancer, take it from your trusted proxy's
header, not from `r.RemoteAddr`, which is then the proxy: use the address your own proxy appended (the last hop you
trust), never a header the end user can set directly. An address with a zone id (`fe80::1%eth0`) is invalid: leave
`RemoteIP` empty then.

## Options

`revokegpt.New(secret, endpoint string, opts ...Option) (*Client, error)`

- `secret`: your site's secret key (`rgsk_...`). A management key (`rgmk_...`) is refused.
- `endpoint`: the full siteverify URL. `https:`, or `http:` only on `localhost` or `127.0.0.1`; no username,
  password, query or fragment; no default. The assessment and password URLs are derived from it, so it must end in
  `/siteverify` for those calls (an `*InputError` otherwise).
- `WithTimeout(d)`: a whole number of milliseconds from 1 ms to 60 s; default 5 s. It is a total deadline for one
  call, from connecting to the last body byte, together with the context you pass: whichever ends first. Nothing is
  retried.
- `WithHTTPClient(hc)`: your own `*http.Client`; see "Proxies and TLS".

`VerifyOptions`

- Give exactly one of `ExpectedHostname` (canonical: lowercase, no trailing dot, no port) and `ExpectedApp`
  (`&ExpectedApp{Platform: "android" | "ios", ID: ...}`, for tokens from the RevokeGPT mobile SDKs).
- `ExpectedAction`: leave it nil only if you use no actions; then a token that carries an action is refused.
- `MinScore`: a number in [0, 1]. Always set it: every verified result carries a score, and without one the outcome
  is `threshold-missing`. Scores come in steps of 0.1; 0.5 is a sensible start (use 0.6 or more for app tokens).
- `RemoteIP`, `SiteKey`: sent only when not empty; a given value is checked first.
- Never choose between the hostname and app expectation from anything the client controls.

## Verify reasons

When `OK` is false, `Reason` is one of:

| Reason | Meaning |
|---|---|
| `invalid-expectation` | Bad expectation (both or neither of hostname and app, a non-canonical hostname, a bad `MinScore`, ...). Nothing was sent. Fix your code. |
| `invalid-options` | A given `RemoteIP` or `SiteKey` is invalid. Nothing was sent. |
| `invalid-token-format` | Not 1 to 2048 characters of `A-Z a-z 0-9 - _`. Nothing was sent. |
| `network-error` | The request failed, timed out, or the context ended. |
| `http-error` | Siteverify answered with a status other than 200 (redirects included), or a body over 64 KiB. |
| `not-verified` | Siteverify did not verify the token (invalid, expired, used), or the body was malformed. `Result.ErrorCodes` says why. |
| `hostname-mismatch` | The token was issued for another hostname. |
| `app-mismatch` | The token was issued to another app, or to a web page or the other platform. |
| `action-mismatch` | Another action, or an action when you expect none. |
| `score-missing` | You set `MinScore` and the result has no score. |
| `threshold-missing` | The result has a score and you set no `MinScore`. |
| `score-below-threshold` | The score is below `MinScore`. |
| `score-invalid` | The score is not a number in [0, 1]. |

Treat every reason as "do not accept". A token is single use: after `network-error` or `http-error` it may already be
spent, so a retry needs a new token from the widget.

## Assessments, account protection, MFA and erase

```go
a, err := client.CreateAssessment(ctx, revokegpt.AssessmentInput{
	Token:          token,
	ExpectedAction: "login",
	UserInfo:       &revokegpt.UserInfo{AccountRef: revokegpt.AccountRef{AccountID: "user-42"}},
	AccountVerification: &revokegpt.AccountVerification{
		Endpoints: []revokegpt.Endpoint{{EmailAddress: email}},
	},
})
if err == nil && a.TokenProperties.Valid && a.RiskAnalysis.Score >= 0.5 {
	// a.Raw has every field of the answer, including ones this SDK does not type yet
}
err = client.Annotate(ctx, a.Name, revokegpt.AnnotateInput{Annotation: "LEGITIMATE", AccountRef: revokegpt.AccountRef{AccountID: "user-42"}})
err = client.EraseAccount(ctx, revokegpt.AccountRef{AccountID: "user-42"})
```

- `CreateAssessment` returns an `*Assessment`. An invalid token is still a 200 with `TokenProperties.Valid == false`
  and score 0: check `Valid`. Reason and label lists are open strings: tolerate unknown values.
- `Annotate` and `EraseAccount` return only an error. Annotate with ground truth you learn later (a chargeback, a
  confirmed fraud, a legitimate purchase), not guesses. An empty `AnnotateInput` is sent, and the service refuses it.
- Use one form of an account id (`AccountID` or `HashedAccountID`) everywhere you assess, annotate and erase.
- `CreateAccountTime` is a `*time.Time`, sent as RFC 3339 UTC with milliseconds; `TransactionEvent.EventTime` is an
  RFC 3339 string, sent as you give it.
- Each feature is off for a site until its flags are set; a closed flag is an `*Error` with code `feature-disabled`
  and status 403.
- Express mode (`Express: true`, no token) scores the IP address alone: pass the real end user's address.

## Payments and SMS

Score a payment before you charge it and an SMS before you send it (needs the site's flags). Payments take only the
card's BIN (first 6 or 8 digits) and last four digits. `CardFields` checks them and returns an `*Error` with code
`bad-request` and status 0 (no request made) for anything else; every string of `TransactionData` is also scanned for
a card number before sending (`ContainsPANRun` is the same scan).

```go
card, err := revokegpt.CardFields("424242", "4242")
value := 59.9
a, err := client.CreateAssessment(ctx, revokegpt.AssessmentInput{
	Token: token, FraudPrevention: "ENABLED",
	TransactionData: &revokegpt.TransactionData{CardBin: card.BIN, CardLastFour: card.Last4, CurrencyCode: "USD", Value: &value},
	UserInfo:        &revokegpt.UserInfo{UserIDs: []revokegpt.UserID{{PhoneNumber: "+447700900123"}}}, // scored for SMS toll fraud
})
// a.FraudPreventionAssessment.TransactionRisk is 0 to 1 (0.5 with Unscored when it could not be scored)
// a.PhoneFraudAssessment.SMSTollFraudVerdict.Risk
err = client.Annotate(ctx, a.Name, revokegpt.AnnotateInput{
	Reasons:          []string{"TRANSACTION_DECLINED"},
	TransactionEvent: &revokegpt.TransactionEvent{EventType: "AUTHORIZATION_DECLINE", Reason: gatewayCode},
})
```

Suggested thresholds: block at risk 0.7 or more, step up at 0.4 or more; nothing is enforced for you. Examples (local
minimal types, no gateway SDK needed):

- [examples/payments/stripe](examples/payments/stripe/main.go), [adyen](examples/payments/adyen/main.go),
  [braintree](examples/payments/braintree/main.go): assess, charge, annotate accepted, declined or chargeback.
- [examples/sms](examples/sms/main.go): gate an SMS on the toll-fraud verdict (an unscored verdict means do not send).
  RevokeGPT never sends the SMS.

## Errors

A bad argument is an `*InputError` before any request (it matches `errors.Is(err, revokegpt.ErrInvalidInput)`, and its
text never shows the value). A failed call is an `*Error`:

```go
var e *revokegpt.Error
if errors.As(err, &e) {
	log.Printf("revokegpt: %s status %d request %s", e.Code, e.Status, e.RequestID)
	if e.RetryAfterSeconds != nil { /* a 429 that carried Retry-After */ }
}
if revokegpt.IsUnavailable(err) { /* HTTP 503: "could not check", never "clean" */ }
```

| Field | Meaning |
|---|---|
| `Code` | `unauthorized`, `feature-disabled`, `not-found`, `expired`, `rate-limited`, `bad-request`, `payload-too-large`, `unsupported-media-type`, `service-unavailable`, `network-error` (timeout, failed request or ended context), `invalid-response` (a body that is not valid), `feature-unavailable` (no pair blinder). Treat the set as open. |
| `Status` | The HTTP status; 0 when nothing was answered or no request was made. |
| `RequestID` | The service's request id, when it sent one (quote it to support). |
| `RetryAfterSeconds` | Set for an answer that carried `Retry-After` as seconds. |

A call that ended because your context was cancelled or the timeout passed is still code `network-error`, and
`errors.Is(err, context.Canceled)` or `errors.Is(err, context.DeadlineExceeded)` matches it.

## Proxies and TLS

The client the SDK creates ignores `HTTP_PROXY` and the other proxy environment variables, so the environment cannot
redirect the secret. To use a proxy or a custom CA, build your own `*http.Client` and pass it with `WithHTTPClient`.
The SDK sends through a copy of it, without following redirects and without its cookie jar; your client is left as it
was. A client with a nil `Transport` uses `http.DefaultTransport`, which does read the proxy variables: that is your
choice. A transport that ignores the request context cannot be interrupted: the call still returns at the deadline,
but the goroutine inside your transport stays until it returns.

## Language notes

- Go has no null: an absent option is a nil pointer or an empty string (`ExpectedAction == nil` expects no action).
  The protocol's "given but null" cases cannot be written (protocol v1 section 22.1a lists them).
- Optional response fields (`Score`, the strings of `SiteverifyResult` and `TokenProperties`) are pointers, nil when
  absent. `Assessment.Raw` is the whole body.
- Hostnames that need the full UTS 46 mapping (a full-width letter, a soft hyphen) are refused as an
  `ExpectedHostname` (`invalid-expectation`): the check fails closed. Pass the punycode form.
- A password, username or free text that is not valid UTF-8 is an `*InputError`.
- A `Client` is safe for concurrent use. Its `fmt`, `log/slog` and `encoding/json` forms are a fixed placeholder.
- Tested on Go 1.26 and 1.27.

## Security notes

- The secret goes only in the POST body (siteverify) or the `Authorization` header (other calls), never in a URL, an
  error, a log line or a printed form.
- Build the siteverify body only with this SDK. If you call siteverify yourself, never concatenate the token into the
  body: an unencoded value injects fields.
- No retries (a token is single use). Redirects are never followed. At most 64 KiB of a JSON answer is read, while it streams.
- `RemoteIP` behind a proxy: see "Trusted client IP".

## Conformance

The shared protocol vectors run in `go test ./...`. The cross-SDK run drives the runner program in `sdks/go/cmd/conformance`,
which needs the build tag `conformance` (`go run -tags conformance ./cmd/conformance`); `tools/sdk-conformance` does that.

## Firewall

To protect routes without writing the checks yourself, see the `firewall` module (`sdks/integrations/go` in this
repository; it will depend on this SDK). It is released separately.

## License

MIT
