// Package jsonx reads response bodies as strict JSON.
//
// The rules follow JSON.parse in the reference SDK: the last duplicate key wins, a byte-order mark or any text
// after the value is an error, NaN and Infinity are not JSON, and an invalid UTF-8 byte is an error (Go's
// decoder would replace it). A number is kept as its text (json.Number), so a huge exponent never fails the
// whole body: the caller decides what a number means. Object keys are matched exactly (no case folding),
// which a typed struct decode would not do.
//
// One difference from JSON.parse: a lone surrogate escape ("\ud800") becomes U+FFFD here, where JavaScript keeps
// the lone surrogate. Both are strings no canonical hostname or edge-issued action can equal.
package jsonx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// Parse returns the value of body: nil, bool, json.Number, string, []any or map[string]any.
func Parse(body []byte) (any, error) {
	if !utf8.Valid(body) {
		return nil, errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return v, nil
}
