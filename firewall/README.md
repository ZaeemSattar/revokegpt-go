# RevokeGPT firewall for Go `net/http`

Module `github.com/ZaeemSattar/revokegpt-go/firewall`. MIT. Go 1.26 or later. It requires the core module
`github.com/ZaeemSattar/revokegpt-go` and uses its public `hostname` package for the hostname rules (the monorepo `go.mod`
has a `replace` to `../../go`, which the mirror export drops, pinning the released core). Otherwise standard library only
(the singleflight is a local copy).

It evaluates the site's signed policy bundle in front of an `http.Handler` with the same decisions
as the reference implementation (`packages/protocol/src/policy`, protocol v1 section 18). The shared
vectors in `packages/protocol/test-vectors/policy.json` are the arbiter; every row passes.

```go
fw, err := firewall.New(firewall.Config{
    SiteKey:    "rgpk_...",
    SecretKey:  "rgsk_...",          // needed for requireToken rules
    PinnedKeys: pinned,              // the owner's real bundle public keys
})
if err != nil { log.Fatal(err) }
log.Fatal(http.ListenAndServe(":8080", fw.Middleware(origin)))
```

## Mount it outside the mux

`http.ServeMux` cleans the path and **redirects `//` and dot segments before your handler runs**.
Mounted inside a mux, the firewall would never see the raw target and `//admin` would arrive as
`/admin`. Wrap the whole mux (or the reverse proxy) instead:

```go
mux := http.NewServeMux()
// ... routes ...
http.ListenAndServe(":8080", fw.Middleware(mux))   // right: the firewall sees r.RequestURI
// http.ListenAndServe(":8080", mux)               // and never: mux.Handle("/", fw.Middleware(...))
```

The firewall matches on `r.RequestURI` (the raw target), never on `r.URL.Path` (already unescaped).
It also strips every `x-rg-*` request header (and the `X_RG_*` forms) before the origin sees them,
then sets `X-RG-Rule`, and `X-RG-Score` / `X-RG-Verdict` / `X-RG-Path` where the decision says so.

## Routing must stay case-sensitive (Ruling 14)

Firewall rules match paths case-sensitively (protocol section 18.3), so `/ADMIN` is not `/admin`. The middleware wraps any handler or reverse proxy, and `http.ServeMux` is case-sensitive. If the origin
behind this integration routes case-insensitively (IIS, a case-folding proxy or framework, a case-insensitive file
system), `/ADMIN` reaches the `/admin` handler while a rule on `/admin` never sees it. Make the origin case-sensitive
or write the rule for each spelling the origin serves.

## Behaviour

- Decisions: `Decide(bundle, request, session, verifyOutcome, now)` is pure. Exported next to it:
  `Normalize`, `CompileGlob` / `GlobMatch`, `HostMatches`, `VerifyBundle`, `VerifySession`,
  `StripRgHeaders`, `IsSafeReturnPath`. They are used by the cross-port differential.
- Action tokens (`requireToken`) come only from the `X-RG-Token` header. The only route that
  reads a body is `POST /__rg/return` (urlencoded, at most 4 KiB, field `rg_clearance`).
- Reserved routes, served before any rule: `POST /__rg/session` (token in `X-RG-Session-Init`)
  and `POST /__rg/return`. Cookies are `__Host-rg_s`, `__Host-rg_c`, `__Host-rg_r`, each
  `HttpOnly; Secure; SameSite=Lax; Path=/`.
- Responses that block, challenge or set a cookie carry `Cache-Control: no-store`; `Vary: Cookie`
  is added when a rule can depend on a cookie. A fetch/XHR request (no `Sec-Fetch-Mode:
  navigate`, or no `text/html` in `Accept`) never gets a redirect, only `403` +
  `X-RG-Action: challenge`.
- Siteverify: `POST /v1/siteverify`, `Authorization: Bearer rgsk_...`, `X-RG-Integration:
  go-net-http/<version>`, 2 s timeout, one retry on a connection error only (never on a timeout),
  never follows a redirect. A circuit breaker opens after 5 consecutive failures for 30 s (then
  the rule's `onError` applies with no call). Tokens outside 20..4096 characters or outside
  base64url and `.` are rejected before any call.
- Bundle: fetched from `GET /v1/policies/<siteKey>` (ETag aware), verified offline (Ed25519 over
  `"rg-policy-v1\0" || exact payload bytes`, with an explicit S < L check before the library call),
  refreshed every 60 s plus 0 to 20 s of jitter in the background (single-flight), kept on
  failure (stale-while-error), and the fail mode applies after `expiresAt + 6 h`. A lower
  `version` than the highest accepted is refused (`VersionStore`, in memory by default; plug in
  a durable one to survive restarts). With no bundle ever verified: `Config.InitialFailMode`
  (`open` by default: requests pass with `X-RG-Verdict: none`; `closed` gives a 503). An authentic 404
  from the policies endpoint (no published policies) always passes. `setHeader` values go to the
  origin only, never into challenge or block responses.
- Logging: one `slog` line per decision with the decision id, the rule index and the action.
  Never a token, cookie, key or query string.

## Keys

`PinnedPolicyKeys` and `PinnedSessionKeys` are **placeholders** that fail closed (`kid`) until the
owner supplies the real public keys; pass them in `Config.PinnedKeys`. Session keys used to verify
cookies come from the verified bundle's `tokenKeys`. The public TEST keys (`TestPolicyKeys()`) are accepted by `New` only when the site key is
non-canonical (e.g. `rgpk_conformance`) AND the API base is loopback (`127.0.0.1`, `::1`,
`localhost`); any other combination is a config error. A canonical site key always checks the
bundle's siteKey. The example pins them with `RG_PIN_TEST_KEYS=1` (conformance runs).

## Known differences and limits

- Host canonicalisation follows the WHATWG URL host parser for ASCII (lower case, IPv4 forms such
  as `0x7f.1`, trailing dot, ports). Without Unicode tables in the standard library, a non-ASCII
  label is accepted only for a conservative letter set that needs no NFC / UTS 46 mapping
  (Latin-1 and Latin Extended-A letters, basic Greek and Cyrillic, CJK ideographs, kana, Hangul
  syllables). Other non-ASCII hosts (fullwidth forms, compatibility characters, soft hyphen,
  combining marks) are refused with a 400 where the reference would map them. Real `Host`
  headers are ASCII (punycode), so this only affects hostile input, and it fails closed. A
  randomised differential against the reference found no host where the two give different
  non-empty answers.
- Go runtime facts (net/http acts before any handler, and cannot be faked from a middleware):
  a request with two `Host` headers or a `Host` header holding non-ASCII bytes (an unpunycoded
  IDN) is answered 400 by the server itself; the `rg-conformance` row that sends a raw IDN
  (`decide/punycode-host-from-unicode`) therefore sees a 400 (still a refusal, never an allow). Browsers send punycode in `Host`.
  `OPTIONS *` is answered 200 by `http.Server` unless you set
  `Server.DisableGeneralOptionsHandler = true`, which the example does; do the same so the
  firewall sees it (and answers 400).
- The `/__rg/` namespace other than the two reserved routes answers 404 and never reaches the origin.
- Absolute-form targets, `CONNECT` authority-form and `OPTIONS *` are not origin-form: they get a 400.
- `X-RG-Sig` (opt-in signed header): when the bundle's settings turn `sigHeader` on and `Config.SigSecret` (at least 16
  characters) is set, requests passed to the origin carry `X-RG-Sig: t=<unix seconds>,v1=<hex HMAC-SHA256>`. The MAC
  covers `t`, the request host, the method, the normalised path (empty if not normalisable), and the `X-RG-Score`,
  `X-RG-Verdict` and `X-RG-Rule` values, joined by `\n`. If the bundle asks but no secret is set, no header is sent and
  one config warning is logged. An inbound `X-RG-Sig` is always stripped.

## Commands

```
go test ./...                                   # all vector sections + middleware tests
go test -run '^$' -fuzz=FuzzNormalize -fuzztime=60s .
go vet ./... && gofmt -l .
go run ./cmd/normalize-stdin < targets.txt      # one raw target per line -> one JSON result per line
```

`example/main.go` runs the firewall as a reverse proxy from `RG_API_BASE`, `RG_SITE_KEY`,
`RG_SECRET_KEY`, `RG_ORIGIN` and `PORT`.
