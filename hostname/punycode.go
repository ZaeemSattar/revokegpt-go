package hostname

// A bounded RFC 3492 Punycode codec, used by CanonicalizeHostname to reject "xn--" labels that
// are not valid punycode and to encode non-ASCII labels. Hand-written to keep the module
// standard-library only.

const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 0x80
	pcMaxInt      = 0x7fffffff
	pcMaxInput    = 63
)

func pcDigitValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c-'0') + 26
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c - 'a')
	}
	return pcBase
}

func pcAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + ((pcBase-pcTMin+1)*delta)/(delta+pcSkew)
}

func pcThreshold(k, bias int) int {
	switch {
	case k <= bias:
		return pcTMin
	case k >= bias+pcTMax:
		return pcTMax
	}
	return k - bias
}

// decodePunycode decodes the part of an ACE label after "xn--". ok is false for input longer
// than 63 bytes, a non-ASCII basic code point, an invalid or truncated digit sequence, an
// overflow, or a decoded value that is not a Unicode scalar value.
func decodePunycode(input string) ([]rune, bool) {
	if len(input) > pcMaxInput {
		return nil, false
	}
	delimiter := -1
	for i := len(input) - 1; i >= 0; i-- {
		if input[i] == '-' {
			delimiter = i
			break
		}
	}
	basic := 0
	if delimiter > 0 {
		basic = delimiter
	}
	output := make([]rune, 0, len(input))
	for j := 0; j < basic; j++ {
		if input[j] >= 0x80 {
			return nil, false
		}
		output = append(output, rune(input[j]))
	}
	n, i, bias := pcInitialN, 0, pcInitialBias
	pos := 0
	if basic > 0 {
		pos = basic + 1
	}
	for pos < len(input) {
		oldi, w := i, 1
		for k := pcBase; ; k += pcBase {
			if pos >= len(input) {
				return nil, false
			}
			digit := pcDigitValue(input[pos])
			pos++
			if digit >= pcBase {
				return nil, false
			}
			if digit > (pcMaxInt-i)/w {
				return nil, false
			}
			i += digit * w
			t := pcThreshold(k, bias)
			if digit < t {
				break
			}
			if w > pcMaxInt/(pcBase-t) {
				return nil, false
			}
			w *= pcBase - t
		}
		length := len(output) + 1
		bias = pcAdapt(i-oldi, length, oldi == 0)
		if i/length > pcMaxInt-n {
			return nil, false
		}
		n += i / length
		i %= length
		if n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff) {
			return nil, false
		}
		output = append(output, 0)
		copy(output[i+1:], output[i:])
		output[i] = rune(n)
		i++
	}
	return output, true
}

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

// encodePunycode encodes a label to the part after "xn--" (RFC 3492 section 6.3).
func encodePunycode(in []rune) (string, bool) {
	out := make([]byte, 0, len(in)+8)
	for _, r := range in {
		if r < 0x80 {
			out = append(out, byte(r))
		}
	}
	b := len(out)
	h := b
	if b > 0 {
		out = append(out, '-')
	}
	n, delta, bias := pcInitialN, 0, pcInitialBias
	for h < len(in) {
		m := pcMaxInt
		for _, r := range in {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		if m-n > (pcMaxInt-delta)/(h+1) {
			return "", false
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range in {
			if int(r) < n {
				delta++
				if delta > pcMaxInt {
					return "", false
				}
			}
			if int(r) == n {
				q := delta
				for k := pcBase; ; k += pcBase {
					t := pcThreshold(k, bias)
					if q < t {
						break
					}
					out = append(out, pcDigit(t+(q-t)%(pcBase-t)))
					q = (q - t) / (pcBase - t)
				}
				out = append(out, pcDigit(q))
				bias = pcAdapt(delta, h+1, h == b)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return string(out), len(out) <= pcMaxInput
}
