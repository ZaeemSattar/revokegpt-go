package jsonx

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	v, err := Parse([]byte(`{"a":1,"a":2,"b":1e999}`))
	m, _ := v.(map[string]any)
	if err != nil || m["a"] != json.Number("2") || m["b"] != json.Number("1e999") {
		t.Fatalf("%v %v", v, err)
	}
	for name, in := range map[string]string{
		"empty": "", "bom": "\xef\xbb\xbf{}", "trailing": "{} {}", "garbage": "{} x", "nan": "NaN", "bad utf8": "{\"a\":\"\xff\"}",
		"truncated": `{"a":`, "deep": strings.Repeat("[", 100000),
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
