// Package revokegpt is the RevokeGPT server SDK for Go: it verifies a response token with siteverify and applies
// the relying-party checks (protocol v1 sections 7 and 22). It uses the standard library only.
//
//	client, err := revokegpt.New(secretKey, "https://api.revokegpt.com/v1/siteverify")
//	if err != nil { ... } // an *InputError, which matches ErrInvalidInput; it never includes the secret
//	action, min := "login", 0.5
//	out := client.Verify(ctx, token, revokegpt.VerifyOptions{
//		ExpectedHostname: "shop.example", ExpectedAction: &action, MinScore: &min,
//	})
//	if !out.OK { /* out.Reason says why */ }
//
// # Behaviour
//
// Verify never returns an error and never panics: every failure is an outcome with a Reason. Bad options are
// reported before any request is made, because a token is single use and a spent one cannot be retried. Nothing
// is retried automatically: after a network failure the token may already be spent.
//
// The timeout (WithTimeout, 5 s by default) is a total deadline for the whole exchange, from the first connect to
// the last body byte, and it holds whatever the http.Client does. A response is read through a size cap (64 KiB)
// while it streams; a larger one is refused, never parsed from a truncated read. Redirects are never followed.
// The secret is sent in the form body only, never in a URL or a header.
//
// # HTTP client
//
// With no WithHTTPClient the SDK uses its own client, which ignores the proxy environment variables (HTTP_PROXY
// and the like); to use a proxy or a custom CA, pass a client that is set up for it. A client you pass is copied:
// the copy never follows redirects and has no cookie jar, and your client is left as it was. The copy keeps your
// Transport and Timeout. The SDK asks for an unencoded answer and refuses one that is encoded anyway.
//
// # Absent and null
//
// Go has no null. Optional request fields are pointers or zero values, and "absent" is nil or empty: a nil
// ExpectedAction means no action is expected. A field the protocol calls "given, but null" (an invalid value)
// cannot be written, and the shared vectors that need one are not run through the Go API; protocol v1
// section 22.1a lists them. Optional response fields (SiteverifyResult.Score and the strings) are pointers, nil
// when the field is absent.
//
// # The secret
//
// The secret key is held in an unexported field. A Client prints as a fixed placeholder through fmt (every verb),
// log/slog and encoding/json, and no error includes it. Do not log a request you build yourself.
package revokegpt
