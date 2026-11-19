// Package keys checks the key formats of protocol v1 (section 2): secret keys with a CRC32 checksum, and
// site keys. Every check is ASCII only.
package keys

import (
	"crypto/subtle"
	"hash/crc32"
	"regexp"
)

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var (
	secretKey = regexp.MustCompile(`\A(rgsk|rgmk)_([0-9A-Za-z]{12})_([0-9A-Za-z]{32})([0-9A-Za-z]{6})\z`)
	siteKey   = regexp.MustCompile(`\Argpk_[0-9A-Za-z]{20}\z`)
)

// checksum is the CRC32 of the body as 6 base62 digits, most significant first, zero-padded.
func checksum(body string) string {
	n := crc32.ChecksumIEEE([]byte(body))
	var out [6]byte
	for i := 5; i >= 0; i-- {
		out[i] = base62[n%62]
		n /= 62
	}
	return string(out[:])
}

// Kind is the kind of a secret key.
type Kind string

// The kinds of key that carry a checksum.
const (
	Secret     Kind = "secret"
	Management Kind = "management"
)

// ParseSecret returns the kind and key id of a well-formed key with a valid checksum, or ok=false.
func ParseSecret(s string) (kind Kind, keyID string, ok bool) {
	m := secretKey.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	sum := m[4]
	body := s[:len(s)-len(sum)]
	if subtle.ConstantTimeCompare([]byte(checksum(body)), []byte(sum)) != 1 {
		return "", "", false
	}
	if m[1] == "rgsk" {
		return Secret, m[2], true
	}
	return Management, m[2], true
}

// IsSiteKey reports whether s is a site key.
func IsSiteKey(s string) bool { return siteKey.MatchString(s) }
