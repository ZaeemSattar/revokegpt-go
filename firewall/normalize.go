package firewall

import (
	"strings"
	"unicode/utf8"
)

// NormalizeResult is the outcome of Normalize. When OK is false, Reason is "invalid" or
// "non-canonical" and Detail names the cause (the same words as the reference implementation).
type NormalizeResult struct {
	OK        bool
	Path      string
	Collapsed string
	Reason    string
	Detail    string
}

func badNorm(reason, detail string) NormalizeResult {
	return NormalizeResult{Reason: reason, Detail: detail}
}

// segmentResult is the outcome of decodeSegment.
type segmentResult struct {
	ok      bool
	text    string
	escaped bool
	reason  string
	detail  string
}

func badSeg(reason, detail string) segmentResult {
	return segmentResult{reason: reason, detail: detail}
}

// nonASCIIMode says what a raw non-ASCII character does: refuse it (requests) or encode it
// as upper-case UTF-8 %XX (globs).
type nonASCIIMode int

const (
	nonASCIIInvalid nonASCIIMode = iota
	nonASCIIEncode
)

// utf8Shape is the length of the UTF-8 sequence led by lead and the valid range of its second
// byte; ok is false for a stray continuation byte, C0, C1 and F5..FF.
func utf8Shape(lead byte) (length int, lo, hi byte, ok bool) {
	switch {
	case lead >= 0xc2 && lead <= 0xdf:
		return 2, 0x80, 0xbf, true
	case lead == 0xe0:
		return 3, 0xa0, 0xbf, true // no overlong
	case lead == 0xed:
		return 3, 0x80, 0x9f, true // no surrogates
	case lead >= 0xe1 && lead <= 0xef:
		return 3, 0x80, 0xbf, true
	case lead == 0xf0:
		return 4, 0x90, 0xbf, true // no overlong
	case lead == 0xf4:
		return 4, 0x80, 0x8f, true // at most U+10FFFF
	case lead >= 0xf1 && lead <= 0xf3:
		return 4, 0x80, 0xbf, true
	}
	return 0, 0, 0, false
}

// keepEncoded: bytes that stay percent-encoded (upper-case hex) in the canonical spelling:
// % ? # space [ ] { } | ^ " < > and backtick.
func keepEncoded(b byte) bool {
	switch b {
	case 0x25, 0x3f, 0x23, 0x20, 0x5b, 0x5d, 0x7b, 0x7d, 0x7c, 0x5e, 0x22, 0x3c, 0x3e, 0x60:
		return true
	}
	return false
}

// decodeSegment is the canonical spelling of one path fragment that holds no "/" (a segment of
// a request path, or a literal piece of a glob segment between "*"). One function for both, so
// a rule and a request meet in the same alphabet (protocol v1, section 18.3, "Decode set").
func decodeSegment(raw string, mode nonASCIIMode) segmentResult {
	out := make([]byte, 0, len(raw))
	escaped := false
	i := 0
	for i < len(raw) {
		c := raw[i]
		if c == '%' {
			var bytes []byte
			for i < len(raw) && raw[i] == '%' {
				h, l := -1, -1
				if i+1 < len(raw) {
					h = hexVal(raw[i+1])
				}
				if i+2 < len(raw) {
					l = hexVal(raw[i+2])
				}
				if h < 0 || l < 0 {
					return badSeg("invalid", "bad-escape")
				}
				bytes = append(bytes, byte(h*16+l))
				i += 3
			}
			escaped = true
			k := 0
			for k < len(bytes) {
				b := bytes[k]
				if b < 0x80 {
					if b == 0x2f || b == 0x5c {
						return badSeg("non-canonical", "encoded-separator")
					}
					if b == 0x3b {
						return badSeg("non-canonical", "encoded-semicolon")
					}
					if b < 0x20 || b == 0x7f {
						return badSeg("non-canonical", "encoded-control")
					}
					if keepEncoded(b) {
						out = appendPct(out, b)
					} else {
						out = append(out, b)
					}
					k++
					continue
				}
				length, lo, hi, ok := utf8Shape(b)
				if !ok || k+length > len(bytes) {
					return badSeg("non-canonical", "invalid-utf8")
				}
				out = appendPct(out, b)
				for j := 1; j < length; j++ {
					cb := bytes[k+j]
					l, h := byte(0x80), byte(0xbf)
					if j == 1 {
						l, h = lo, hi
					}
					if cb < l || cb > h {
						return badSeg("non-canonical", "invalid-utf8")
					}
					out = appendPct(out, cb)
				}
				k += length
			}
			continue
		}
		if c == 0x3b {
			return badSeg("non-canonical", "path-parameter")
		}
		if c == 0x5c {
			return badSeg("invalid", "backslash")
		}
		if c < 0x20 || c == 0x7f {
			return badSeg("invalid", "control-character")
		}
		if c == 0x3f || c == 0x23 {
			return badSeg("invalid", "reserved-character")
		}
		if c > 0x7e {
			if mode == nonASCIIInvalid {
				return badSeg("invalid", "non-ascii")
			}
			r, size := utf8.DecodeRuneInString(raw[i:])
			if r == utf8.RuneError && size <= 1 {
				return badSeg("invalid", "lone-surrogate")
			}
			var buf [4]byte
			n := utf8.EncodeRune(buf[:], r)
			for _, bb := range buf[:n] {
				out = appendPct(out, bb)
			}
			i += size
			continue
		}
		if keepEncoded(c) {
			out = appendPct(out, c)
		} else {
			out = append(out, c)
		}
		i++
	}
	return segmentResult{ok: true, text: string(out), escaped: escaped}
}

// removeDotSegments is RFC 3986 5.2.4 on a path that starts with "/". Empty segments are kept.
func removeDotSegments(path string) string {
	segs := strings.Split(path, "/")
	out := make([]string, 0, len(segs))
	trailing := false
	for i := 1; i < len(segs); i++ {
		s := segs[i]
		last := i == len(segs)-1
		switch s {
		case ".":
			trailing = last
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			trailing = last
		default:
			out = append(out, s)
			trailing = false
		}
	}
	if trailing {
		out = append(out, "")
	}
	return "/" + strings.Join(out, "/")
}

func dropTrailingSlash(p string) string {
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		return p[:len(p)-1]
	}
	return p
}

func collapseSlashes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '/' && i > 0 && s[i-1] == '/' {
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Normalize turns a raw request target (origin-form: path and optional query) into the strings
// rules match on (protocol v1, section 18.3). Pass r.RequestURI, never r.URL.Path: the standard
// library has already unescaped and (in a ServeMux) cleaned the latter.
//
// Path keeps repeated slashes after dot-segment removal; Collapsed merges repeated slashes first
// and then removes dot segments. A decision evaluates both and takes the stricter result.
func Normalize(rawTarget string) NormalizeResult {
	for i := 0; i < len(rawTarget); i++ {
		c := rawTarget[i]
		if c < 0x20 || c == 0x7f {
			return badNorm("invalid", "control-character")
		}
	}
	if len(rawTarget) == 0 || rawTarget[0] != '/' {
		return badNorm("invalid", "not-origin-form")
	}
	end := len(rawTarget)
	if i := strings.IndexAny(rawTarget, "?#"); i >= 0 {
		end = i
	}
	raw := rawTarget[:end]
	// The reference counts UTF-16 code units; keep the same order of checks and the same limit.
	if utf16Len(raw) > maxRawPathBytes {
		return badNorm("non-canonical", "path-too-long")
	}
	parts := strings.Split(raw, "/")
	var decoded strings.Builder
	decoded.Grow(len(raw))
	for i, p := range parts {
		r := decodeSegment(p, nonASCIIInvalid)
		if !r.ok {
			return badNorm(r.reason, r.detail)
		}
		if (r.text == "." || r.text == "..") && r.escaped {
			return badNorm("non-canonical", "encoded-dot-segment")
		}
		if i > 0 {
			decoded.WriteByte('/')
		}
		decoded.WriteString(r.text)
	}
	d := decoded.String()
	return NormalizeResult{
		OK:        true,
		Path:      dropTrailingSlash(removeDotSegments(d)),
		Collapsed: dropTrailingSlash(removeDotSegments(collapseSlashes(d))),
	}
}
