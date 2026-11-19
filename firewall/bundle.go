package firewall

import (
	"bytes"
	"unicode/utf8"
)

// BundleExpect names the site a bundle must be for. SiteKey is optional.
type BundleExpect struct {
	SiteID  string
	SiteKey string
	// AnySite skips the siteId check. Only an integration that learns the site id from its
	// first verified bundle sets it.
	AnySite bool
}

// BundleResult is the outcome of VerifyBundle. Reason is one of size, schema, kid, sig, site,
// rollback, not-yet, expired when OK is false.
type BundleResult struct {
	OK      bool
	Payload *Payload
	Bytes   []byte
	Reason  string
}

func failBundle(reason string) BundleResult { return BundleResult{Reason: reason} }

// VerifyBundle verifies a served bundle (protocol v1, section 18.5). Reasons, in the order they
// are checked: size, schema (the envelope), kid, sig, schema (the payload), site, rollback,
// not-yet, expired. The signature is checked over the exact decoded payload bytes; nothing is
// re-serialised, and a bad signature is never partially trusted.
func VerifyBundle(served string, pinned []Key, now, minVersion int64, expect BundleExpect) BundleResult {
	if utf16Len(served) > maxServedBytes {
		return failBundle("size")
	}
	envAny, err := decodeJSON([]byte(served))
	if err != nil {
		return failBundle("schema")
	}
	env, ok := envAny.(obj)
	if !ok || len(env) != 4 {
		return failBundle("schema")
	}
	alg, ok1 := asString(env["alg"])
	kid, ok2 := asString(env["kid"])
	payloadB64, ok3 := asString(env["payload"])
	sigB64, ok4 := asString(env["sig"])
	if !ok1 || !ok2 || !ok3 || !ok4 || alg != "Ed25519" {
		return failBundle("schema")
	}
	payload, okp := fromBase64URL(payloadB64)
	sig, oks := fromBase64URL(sigB64)
	if !okp || !oks {
		return failBundle("schema")
	}
	if len(payload) > maxBundleBytes {
		return failBundle("size")
	}
	var key *Key
	for i := range pinned {
		if pinned[i].Kid == kid && pinned[i].Alg == alg {
			key = &pinned[i]
			break
		}
	}
	if key == nil || !keyIsConsistent(*key) || now > key.NotAfter {
		return failBundle("kid")
	}
	if !verifyDomain(*key, policySignatureDomain, payload, sig) {
		return failBundle("sig")
	}
	// UTF-8 JSON, as TextDecoder (fatal) reads it: a leading BOM is dropped.
	text := bytes.TrimPrefix(payload, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(text) {
		return failBundle("schema")
	}
	p, err := ParsePayload(text)
	if err != nil {
		return failBundle("schema")
	}
	if !expect.AnySite && p.SiteID != expect.SiteID {
		return failBundle("site")
	}
	if expect.SiteKey != "" && p.SiteKey != expect.SiteKey {
		return failBundle("site")
	}
	if p.Version < minVersion {
		return failBundle("rollback")
	}
	if p.NotBefore > now+clockSkewSeconds {
		return failBundle("not-yet")
	}
	if now > p.ExpiresAt+clockSkewSeconds {
		return failBundle("expired")
	}
	return BundleResult{OK: true, Payload: p, Bytes: payload}
}

// Freshness of a cached, verified bundle at now: "fresh" (until expiresAt plus 300 s skew),
// "grace" (stale-while-error, until expiresAt plus 6 h), "expired" (the fail mode applies) or
// "not-yet".
func Freshness(p *Payload, now int64) string {
	switch {
	case p.NotBefore > now+clockSkewSeconds:
		return "not-yet"
	case now <= p.ExpiresAt+clockSkewSeconds:
		return "fresh"
	case now <= p.ExpiresAt+staleGraceSeconds:
		return "grace"
	}
	return "expired"
}
