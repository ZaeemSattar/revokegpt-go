package firewall

import (
	"unicode/utf8"
)

// utf16Len is the length of s in UTF-16 code units, which is what the reference
// implementation (JavaScript string length) counts for every length limit. An invalid
// byte counts as one unit (it would read as U+FFFD).
func utf16Len(s string) int {
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
		i += size
	}
	return n
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}

const upperHex = "0123456789ABCDEF"

func appendPct(b []byte, c byte) []byte {
	return append(b, '%', upperHex[c>>4], upperHex[c&15])
}
