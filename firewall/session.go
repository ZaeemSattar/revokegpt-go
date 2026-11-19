package firewall

import (
	"bytes"
	"sort"
	"strings"
	"unicode/utf8"
)

// SessionState is the offline verdict on a session or clearance token. Kind is "none" (no
// token), "valid" (Lvl 0 session, 1 PoW clearance, 2 puzzle clearance; Sc score bucket 0-3) or
// "invalid".
type SessionState struct {
	Kind string `json:"kind"`
	Lvl  int    `json:"lvl,omitempty"`
	Sc   int    `json:"sc,omitempty"`
}

// SessionExpect is the site and the host a token must have been issued for.
type SessionExpect struct {
	SiteID string
	Host   string
}

// SessionBounds are the bundle's minIat and revokedJti.
type SessionBounds struct {
	MinIat     int64
	RevokedJti []string
}

// SessionClaims are the claims of a verified token.
type SessionClaims struct {
	Sid  string
	Host string
	Iat  int64
	Exp  int64
	Max  int64
	Lvl  int
	Sc   int
	Jti  string
}

func invalidSession() SessionState { return SessionState{Kind: "invalid"} }

// VerifySession verifies a session or clearance token offline (protocol v1, section 18.6). An
// empty token is "none"; every failure is "invalid", and the caller then treats the request as
// having no session (no siteverify call is made for it).
func VerifySession(token string, keys []Key, expect SessionExpect, b SessionBounds, now int64) SessionState {
	s, _ := verifySessionClaims(token, keys, expect, b, now)
	return s
}

// VerifySessionClaims is VerifySession that also returns the claims of a valid token.
func VerifySessionClaims(token string, keys []Key, expect SessionExpect, b SessionBounds, now int64) (SessionState, *SessionClaims) {
	return verifySessionClaims(token, keys, expect, b, now)
}

var claimKeys = func() string {
	k := []string{"exp", "host", "iat", "jti", "lvl", "max", "sc", "sid"}
	sort.Strings(k)
	return strings.Join(k, ",")
}()

func verifySessionClaims(token string, keys []Key, expect SessionExpect, b SessionBounds, now int64) (SessionState, *SessionClaims) {
	if token == "" {
		return SessionState{Kind: "none"}, nil
	}
	if utf16Len(token) > maxSessionTokenLen {
		return invalidSession(), nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return invalidSession(), nil
	}
	kid, p, s := parts[1], parts[2], parts[3]
	if !reKid.MatchString(kid) {
		return invalidSession(), nil
	}
	var key *Key
	for i := range keys {
		if keys[i].Kid == kid {
			key = &keys[i]
			break
		}
	}
	if key == nil || !keyIsConsistent(*key) || now > key.NotAfter {
		return invalidSession(), nil
	}
	payload, okp := fromBase64URL(p)
	sig, oks := fromBase64URL(s)
	if !okp || !oks {
		return invalidSession(), nil
	}
	if !verifyDomain(*key, sessionSignatureDomain, payload, sig) {
		return invalidSession(), nil
	}
	text := bytes.TrimPrefix(payload, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(text) {
		return invalidSession(), nil
	}
	jAny, err := decodeJSON(text)
	if err != nil {
		return invalidSession(), nil
	}
	c, ok := jAny.(obj)
	if !ok {
		return invalidSession(), nil
	}
	names := make([]string, 0, len(c))
	for k := range c {
		names = append(names, k)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != claimKeys {
		return invalidSession(), nil
	}
	sid, ok1 := asString(c["sid"])
	host, ok2 := asString(c["host"])
	jti, ok3 := asString(c["jti"])
	if !ok1 || !ok2 || !ok3 {
		return invalidSession(), nil
	}
	iat, ok4 := asInt(c["iat"], 0, maxSafeInteger)
	exp, ok5 := asInt(c["exp"], 0, maxSafeInteger)
	max, ok6 := asInt(c["max"], 1, 86400)
	if !ok4 || !ok5 || !ok6 {
		return invalidSession(), nil
	}
	lvl, ok7 := asInt(c["lvl"], 0, 2)
	sc, ok8 := asInt(c["sc"], 0, 3)
	if !ok7 || !ok8 || !reJti.MatchString(jti) {
		return invalidSession(), nil
	}
	want, okh := RequestHost(expect.Host)
	if sid != expect.SiteID || !okh || host != want {
		return invalidSession(), nil
	}
	if iat > now+clockSkewSeconds {
		return invalidSession(), nil
	}
	if now >= exp || exp > iat+max || now > iat+max {
		return invalidSession(), nil
	}
	if iat < b.MinIat {
		return invalidSession(), nil
	}
	for _, r := range b.RevokedJti {
		if r == jti {
			return invalidSession(), nil
		}
	}
	return SessionState{Kind: "valid", Lvl: int(lvl), Sc: int(sc)},
		&SessionClaims{Sid: sid, Host: host, Iat: iat, Exp: exp, Max: max, Lvl: int(lvl), Sc: int(sc), Jti: jti}
}
