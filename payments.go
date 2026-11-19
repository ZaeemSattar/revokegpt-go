package revokegpt

import "regexp"

// Card-number safety for payments (protocol v1 section 20.1): the card-number (PAN) scan, the field-aware walker
// over transactionData, and CardFields. A card number never leaves the process: a hit is an *Error with code
// "bad-request" and status 0 (status 0 means no request was made), and its text never includes the value.

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func luhn(digits []byte) bool {
	total, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		total += d
		double = !double
	}
	return total%10 == 0
}

// ContainsPANRun reports whether s holds a likely card number. Each run of ASCII digits with at most one space or
// dash between two digits is split on those separators into groups, and any contiguous sequence of whole groups
// with 13 to 19 digits in total that passes the Luhn check is a hit (so a card number next to a CVV, a year or a
// date is still found). A single unseparated run of 20 or more digits is not flagged (an order id). Other
// scripts' digits are not digits here.
func ContainsPANRun(s string) bool {
	for i := 0; i < len(s); {
		if !isDigit(s[i]) {
			i++
			continue
		}
		var groups [][]byte
		j := i
		for {
			start := j
			for j < len(s) && isDigit(s[j]) {
				j++
			}
			groups = append(groups, []byte(s[start:j]))
			if j+1 < len(s) && (s[j] == ' ' || s[j] == '-') && isDigit(s[j+1]) {
				j++
				continue
			}
			break
		}
		for a := range groups {
			var digits []byte
			for b := a; b < len(groups); b++ {
				digits = append(digits, groups[b]...)
				if len(digits) > 19 {
					break
				}
				if len(digits) >= 13 && luhn(digits) {
					return true
				}
			}
		}
		i = j
	}
	return false
}

var e164 = regexp.MustCompile(`\A\+[1-9][0-9]{6,14}\z`)

func hasPAN(v any) bool {
	switch x := v.(type) {
	case string:
		return ContainsPANRun(x)
	case []any:
		for _, e := range x {
			if hasPAN(e) {
				return true
			}
		}
	case wireObj:
		for _, e := range x {
			if hasPAN(e) {
				return true
			}
		}
	}
	return false
}

// userHasPAN scans a buyer or a merchant. Two fields are exempt because their own format already says what they
// hold: creationMs is at most 13 digits (epoch milliseconds) and an E.164 phoneNumber is a phone number. A
// phoneNumber that is not E.164 is scanned like any other string.
func userHasPAN(u wireObj) bool {
	for k, v := range u {
		if k == "creationMs" {
			continue
		}
		if s, ok := v.(string); ok && k == "phoneNumber" && e164.MatchString(s) {
			continue
		}
		if hasPAN(v) {
			return true
		}
	}
	return false
}

var errCardNumber = &Error{Code: "bad-request"}

// scanTransactionData scans every string value of a wire-form transactionData for a card number, except a user's
// (or merchant's) creationMs and E.164 phoneNumber.
func scanTransactionData(d wireObj) error {
	for k, v := range d {
		hit := false
		switch u := v.(type) {
		case wireObj:
			if k == "user" {
				hit = userHasPAN(u)
			} else {
				hit = hasPAN(u)
			}
		case []any:
			if k == "merchants" {
				for _, m := range u {
					if mu, ok := m.(wireObj); ok {
						hit = hit || userHasPAN(mu)
					} else {
						hit = hit || hasPAN(m)
					}
				}
			} else {
				hit = hasPAN(u)
			}
		default:
			hit = hasPAN(v)
		}
		if hit {
			return &Error{Code: errCardNumber.Code}
		}
	}
	return nil
}

var (
	cardBinRE   = regexp.MustCompile(`\A(?:[0-9]{6}|[0-9]{8})\z`)
	cardLast4RE = regexp.MustCompile(`\A[0-9]{4}\z`)
)

// Card is the card fields of TransactionData: the BIN (first 6 or 8 digits) and the last four digits. An empty
// field is "not given".
type Card struct{ BIN, Last4 string }

// CardFields checks a BIN (6 or 8 digits) and the last four digits of a card, and returns them as the fields of
// TransactionData (CardBin and CardLastFour). It is validated locally, so a card number can never be sent by
// mistake: anything that is not 6 or 8 digits and 4 digits is an *Error with code "bad-request" and status 0 (no
// request was made). The error never includes the value. An empty argument is not given.
func CardFields(bin, last4 string) (Card, error) {
	if bin != "" && !cardBinRE.MatchString(bin) || last4 != "" && !cardLast4RE.MatchString(last4) {
		return Card{}, &Error{Code: "bad-request"}
	}
	return Card{BIN: bin, Last4: last4}, nil
}
