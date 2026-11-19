// Package ip canonicalizes IP address text the way the `remoteip` schema of protocol v1 (section 10) accepts it.
//
// It accepts strict dotted-decimal IPv4 and IPv6 with hex groups of 1 to 4 digits, at most one "::" and an
// optional strict dotted-quad tail. No zone id, brackets or whitespace. It is written out by hand, because
// net/netip accepts other spellings (zones) and its rules may move between Go releases.
package ip

import (
	"strconv"
	"strings"
)

// MaxLength is the longest accepted text.
const MaxLength = 45

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// octet is 0 to 255 in plain decimal: no leading zero, ASCII digits only.
func octet(s string) (int, bool) {
	if s == "" || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, n <= 255
}

func parseIPv4(s string) ([4]int, bool) {
	var out [4]int
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return out, false
	}
	for i, p := range parts {
		n, ok := octet(p)
		if !ok {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func parseGroups(s string) ([]int, bool) {
	if s == "" {
		return nil, true
	}
	var out []int
	for _, g := range strings.Split(s, ":") {
		if len(g) < 1 || len(g) > 4 {
			return nil, false
		}
		for i := 0; i < len(g); i++ {
			if !isHex(g[i]) {
				return nil, false
			}
		}
		n, err := strconv.ParseUint(g, 16, 16)
		if err != nil {
			return nil, false
		}
		out = append(out, int(n))
	}
	return out, true
}

func parseIPv6(s string) ([8]int, bool) {
	var g [8]int
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) && s[i] != ':' && s[i] != '.' {
			return g, false
		}
	}
	head := s
	var tail []int
	if strings.Contains(s, ".") {
		colon := strings.LastIndexByte(s, ':')
		if colon == -1 {
			return g, false
		}
		v4, ok := parseIPv4(s[colon+1:])
		if !ok {
			return g, false
		}
		tail = []int{v4[0]<<8 | v4[1], v4[2]<<8 | v4[3]}
		head = s[:colon+1]
		if !strings.HasSuffix(head, "::") {
			head = head[:len(head)-1]
		}
	}
	halves := strings.Split(head, "::")
	if len(halves) > 2 {
		return g, false
	}
	var groups []int
	if len(halves) == 2 {
		left, ok1 := parseGroups(halves[0])
		right, ok2 := parseGroups(halves[1])
		if !ok1 || !ok2 {
			return g, false
		}
		explicit := len(left) + len(right) + len(tail)
		if explicit > 7 {
			return g, false
		}
		groups = append(groups, left...)
		groups = append(groups, make([]int, 8-explicit)...)
		groups = append(groups, right...)
		groups = append(groups, tail...)
	} else {
		var ok bool
		groups, ok = parseGroups(head)
		if !ok || len(groups)+len(tail) != 8 {
			return g, false
		}
		groups = append(groups, tail...)
	}
	copy(g[:], groups)
	return g, true
}

func formatIPv6(g [8]int) string {
	bestStart, bestLen := -1, 1
	for i := 0; i < 8; {
		if g[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && g[j] == 0 {
			j++
		}
		if j-i > bestLen {
			bestStart, bestLen = i, j-i
		}
		i = j
	}
	hexed := func(xs []int) string {
		parts := make([]string, len(xs))
		for i, x := range xs {
			parts[i] = strconv.FormatInt(int64(x), 16)
		}
		return strings.Join(parts, ":")
	}
	if bestStart == -1 {
		return hexed(g[:])
	}
	return hexed(g[:bestStart]) + "::" + hexed(g[bestStart+bestLen:])
}

// Canonical returns the RFC 5952 text of an IPv4 or IPv6 address (an IPv4-mapped one as its dotted quad), or
// ok=false.
func Canonical(s string) (string, bool) {
	if len(s) > MaxLength {
		return "", false
	}
	if !strings.Contains(s, ":") {
		v4, ok := parseIPv4(s)
		if !ok {
			return "", false
		}
		return strconv.Itoa(v4[0]) + "." + strconv.Itoa(v4[1]) + "." + strconv.Itoa(v4[2]) + "." + strconv.Itoa(v4[3]), true
	}
	g, ok := parseIPv6(s)
	if !ok {
		return "", false
	}
	if g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0xffff {
		hi, lo := g[6], g[7]
		return strconv.Itoa(hi>>8) + "." + strconv.Itoa(hi&0xff) + "." + strconv.Itoa(lo>>8) + "." + strconv.Itoa(lo&0xff), true
	}
	return formatIPv6(g), true
}
