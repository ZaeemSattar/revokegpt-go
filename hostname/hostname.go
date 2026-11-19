// Package hostname canonicalizes hostnames the way the RevokeGPT edge does (protocol v1, section 3): the
// WHATWG URL host parser for ASCII input and a conservative IDNA subset for the rest. It is standard
// library only. The SDK uses it to check an expected hostname; the firewall integration shares it.
//
// A hostname that would need the full UTS 46 mapping or newer Unicode tables is refused, never mapped to a
// different host (it fails closed).
package hostname

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const hostnameMaxLength = 253

var hostnameLabels = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

// hostnameForbidden: whitespace (the ECMAScript \s set), C0 and C1 controls, DEL, and the
// delimiters / ? # @ : \ % * (protocol v1, section 3).
func hostnameForbidden(r rune) bool {
	switch {
	case r <= 0x20, r >= 0x7f && r <= 0xa0:
		return true
	case r == 0x1680, r >= 0x2000 && r <= 0x200a, r == 0x2028, r == 0x2029, r == 0x202f, r == 0x205f, r == 0x3000, r == 0xfeff:
		return true
	}
	switch r {
	case '/', '?', '#', '@', ':', '\\', '%', '*':
		return true
	}
	return false
}

// Canonicalize returns the canonical form of a bare hostname, or ok=false. It follows
// the reference (the WHATWG URL host parser, then a canonical-shape check) for ASCII input,
// including IPv4 normalisation ("0x7f.1" is 127.0.0.1). Non-ASCII input is accepted only for a
// conservative set of letters that need no NFC or UTS 46 mapping table (see idnaRuneOK);
// anything else is refused, which fails closed (a 400).
// IPv6 is unsupported, as in the reference.
func Canonicalize(input string) (string, bool) {
	if input == "" {
		return "", false
	}
	ascii := true
	for _, r := range input {
		if hostnameForbidden(r) {
			return "", false
		}
		if r >= 0x80 {
			ascii = false
		}
	}
	if !utf8.ValidString(input) {
		return "", false
	}
	host := input
	if !ascii {
		h, ok := idnaToASCII(input)
		if !ok {
			return "", false
		}
		host = h
	} else {
		host = strings.ToLower(host)
	}
	// WHATWG: a host whose last label is a number is an IPv4 address (or a failure).
	if endsInANumber(host) {
		v4, ok := parseIPv4(host)
		if !ok {
			return "", false
		}
		host = v4
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) > hostnameMaxLength || !hostnameLabels.MatchString(host) {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if strings.HasPrefix(label, "xn--") && !isRoundTripPunycodeLabel(label) {
			return "", false
		}
	}
	return host, true
}

// idnaRuneOK reports whether a rune may appear in a non-ASCII label. Only characters that are
// already in NFC and whose UTS 46 mapping is the simple lower-case mapping (or nothing) are
// accepted: Latin-1 and Latin Extended-A letters (minus the compatibility digraphs and the
// dotted capital I), basic Greek and Cyrillic, CJK ideographs, Hiragana, Katakana and Hangul
// syllables. Anything else makes the host non-canonical (a 400), which fails closed; the standard
// library has no normalisation tables.
func idnaRuneOK(r rune) bool {
	switch {
	case r < 0x80:
		return true
	case r >= 0xc0 && r <= 0xff:
		return r != 0xd7 && r != 0xf7
	case r >= 0x100 && r <= 0x17f:
		switch r {
		case 0x130, 0x132, 0x133, 0x13f, 0x140, 0x149, 0x17f:
			return false
		}
		return true
	case r >= 0x391 && r <= 0x3a9 && r != 0x3a2, r >= 0x3b1 && r <= 0x3c9:
		return true
	case r >= 0x400 && r <= 0x45f:
		return true
	case r >= 0x3041 && r <= 0x3096, r >= 0x30a1 && r <= 0x30fa:
		return true
	case r >= 0x4e00 && r <= 0x9fff, r >= 0xac00 && r <= 0xd7a3:
		return true
	}
	return false
}

func idnaToASCII(s string) (string, bool) {
	labels := strings.Split(s, ".")
	for i, l := range labels {
		nonASCII := false
		runes := make([]rune, 0, len(l))
		for _, r := range l {
			if !idnaRuneOK(r) {
				return "", false
			}
			if r >= 0x80 {
				nonASCII = true
			}
			runes = append(runes, unicode.ToLower(r))
		}
		if !nonASCII {
			labels[i] = strings.ToLower(l)
			continue
		}
		enc, ok := encodePunycode(runes)
		if !ok {
			return "", false
		}
		labels[i] = "xn--" + enc
	}
	return strings.Join(labels, "."), true
}

func isRoundTripPunycodeLabel(label string) bool {
	decoded, ok := decodePunycode(label[4:])
	if !ok {
		return false
	}
	nonASCII := false
	for _, cp := range decoded {
		if cp >= 0x80 {
			nonASCII = true
		}
		if !idnaRuneOK(cp) || unicode.ToLower(cp) != cp {
			return false
		}
	}
	if !nonASCII {
		return false
	}
	enc, ok := encodePunycode(decoded)
	return ok && "xn--"+enc == label
}

// endsInANumber is the WHATWG "ends in a number" checker.
func endsInANumber(host string) bool {
	parts := strings.Split(host, ".")
	if parts[len(parts)-1] == "" {
		if len(parts) == 1 {
			return false
		}
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	if len(last) >= 2 && last[0] == '0' && (last[1] == 'x' || last[1] == 'X') {
		return strings.Trim(last[2:], "0123456789abcdefABCDEF") == ""
	}
	return false
}

func parseIPv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s, base = s[2:], 16
	} else if len(s) >= 2 && s[0] == '0' {
		s, base = s[1:], 8
	}
	if s == "" {
		return 0, true
	}
	v, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// parseIPv4 is the WHATWG IPv4 parser; the result is dotted-quad text.
func parseIPv4(host string) (string, bool) {
	parts := strings.Split(host, ".")
	if parts[len(parts)-1] == "" && len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return "", false
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, ok := parseIPv4Number(p)
		if !ok {
			return "", false
		}
		nums[i] = n
	}
	for i := 0; i < len(nums)-1; i++ {
		if nums[i] > 255 {
			return "", false
		}
	}
	last := nums[len(nums)-1]
	limit := uint64(1) << (8 * uint(5-len(nums)))
	if last >= limit {
		return "", false
	}
	ip := last
	for i := 0; i < len(nums)-1; i++ {
		ip += nums[i] << (8 * uint(3-i))
	}
	return strconv.FormatUint(ip>>24&255, 10) + "." + strconv.FormatUint(ip>>16&255, 10) + "." +
		strconv.FormatUint(ip>>8&255, 10) + "." + strconv.FormatUint(ip&255, 10), true
}

var numericLastLabel = regexp.MustCompile(`(?:^|\.)(?:[0-9]+|0x[a-z0-9-]*)$`)

// IsValidPattern: a canonical exact hostname, or "*." plus a canonical hostname with
// at least two labels whose last label is not numeric.
func IsValidPattern(p string) bool {
	if strings.HasPrefix(p, "*.") {
		base := p[2:]
		if !strings.Contains(base, ".") {
			return false
		}
		c, ok := Canonicalize(base)
		return ok && c == base && !numericLastLabel.MatchString(base)
	}
	c, ok := Canonicalize(p)
	return ok && c == p
}

// Matches reports whether host equals the exact pattern, or is a strict subdomain of a "*." pattern.
func Matches(host, pattern string) bool {
	if !IsValidPattern(pattern) {
		return false
	}
	h, ok := Canonicalize(host)
	if !ok {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return h != base && strings.HasSuffix(h, "."+base)
	}
	return h == pattern
}

// RequestHost is the canonical host of a request: the Host header with an optional ":port"
// removed, then Canonicalize. ok is false for anything else (IPv6 literals, userinfo,
// an empty host, a port above 65535).
func RequestHost(host string) (string, bool) {
	name, port := host, ""
	if i := strings.IndexByte(host, ':'); i >= 0 {
		name, port = host[:i], host[i+1:]
		if port == "" || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
			return "", false
		}
		if n, _ := strconv.Atoi(port); n > 65535 {
			return "", false
		}
	}
	return Canonicalize(name)
}

// HostMatches matches a rule host pattern (exact canonical host or "*.example.com", never the
// apex) against a request host. A port in the request host is stripped first.
func HostMatches(pattern, host string) bool {
	h, ok := RequestHost(host)
	return ok && Matches(h, pattern)
}
