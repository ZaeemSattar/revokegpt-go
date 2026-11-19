package revokegpt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZaeemSattar/revokegpt-go/internal/schema"
)

func TestPANScanVectors(t *testing.T) {
	cases := loadVector(t, "pan-scan.json").Cases
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range cases {
		text, _ := obj(c["input"])["text"].(string)
		want := obj(c["expected"])["pan"] == true
		if got := ContainsPANRun(text); got != want {
			t.Errorf("%s: ContainsPANRun = %v, want %v", c["name"], got, want)
		}
	}
}

func TestThePANScanIsASCIIOnlyAndTotal(t *testing.T) {
	for _, s := range []string{strings.Repeat("٤٢٤٢", 4), "", "４２４２４２４２４２４２４２４２", strings.Repeat("9", 100000)} {
		if ContainsPANRun(s) {
			t.Errorf("%q flagged", s[:min(len(s), 20)])
		}
	}
	for _, s := range []string{"4242424242424242", "4242 4242 4242 4242", "4242-4242-4242-4242", "x 4242424242424242 y", "4242 4242 4242 4242 123", "123 4242424242424242"} {
		if !ContainsPANRun(s) {
			t.Errorf("%q not flagged", s)
		}
	}
	// A double separator ends a run; 20 unseparated digits are an order id.
	for _, s := range []string{"4242  4242  4242  4242", "42424242424242424242", "4242 4242 4242 4241"} {
		if ContainsPANRun(s) {
			t.Errorf("%q flagged", s)
		}
	}
}

// acceptedTD is the walker and the schema, as CreateAssessment runs them.
func acceptedTD(t *testing.T, d any) bool {
	t.Helper()
	m, ok := d.(map[string]any)
	if !ok {
		return false
	}
	if scanTransactionData(m) != nil {
		return false
	}
	return schema.TransactionData(m)
}

func TestTransactionDataVectors(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(vectorsDir(t), "transaction-data.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	valid, invalid := raw["valid"].([]any), raw["invalid"].([]any)
	if len(valid) != 9 || len(invalid) != 22 {
		t.Fatalf("%d valid, %d invalid", len(valid), len(invalid))
	}
	for _, c := range valid {
		cm := obj(c)
		if !acceptedTD(t, strictValue(t, obj(obj(cm["input"]))["transactionData"])) {
			t.Errorf("valid case refused: %v", cm["name"])
		}
	}
	for _, c := range invalid {
		cm := obj(c)
		if acceptedTD(t, strictValue(t, obj(obj(cm["input"]))["transactionData"])) {
			t.Errorf("invalid case accepted: %v", cm["name"])
		}
	}
}

func TestExemptFieldsAreExemptOnlyInUserAndMerchants(t *testing.T) {
	panPhone := "+883510012345005" // Luhn-valid and E.164: a phone number
	if !acceptedTD(t, map[string]any{"user": map[string]any{"phoneNumber": panPhone}, "merchants": []any{map[string]any{"phoneNumber": panPhone, "creationMs": "4242424242424"}}}) {
		t.Error("exempt fields refused")
	}
	for name, d := range map[string]map[string]any{
		"items":                {"items": []any{map[string]any{"name": panPhone}}},
		"non e164 phone":       {"user": map[string]any{"phoneNumber": "4242424242424242"}},
		"merchant account":     {"merchants": []any{map[string]any{"accountId": "4242 4242 4242 4242"}}},
		"address":              {"shippingAddress": map[string]any{"address": []any{"4242 4242 4242 4242"}}},
		"creationMs elsewhere": {"user": map[string]any{"accountId": "4242424242424242", "creationMs": "1"}},
	} {
		if acceptedTD(t, d) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestACardNumberMakesNoRequestAndIsNotEchoed(t *testing.T) {
	pan := "4242424242424242"
	for name, call := range map[string]func(*Client) error{
		"item name": func(c *Client) error {
			return create(c, AssessmentInput{Token: "t", TransactionData: &TransactionData{Items: []TransactionItem{{Name: pan}}}})
		},
		"gateway": func(c *Client) error {
			return create(c, AssessmentInput{Token: "t", TransactionData: &TransactionData{GatewayInfo: &GatewayInfo{GatewayResponseCode: "4242-4242-4242-4242"}}})
		},
		"transaction id before schema": func(c *Client) error {
			return create(c, AssessmentInput{Token: "t", TransactionData: &TransactionData{TransactionID: pan, CardBin: "1"}})
		},
		"event reason": func(c *Client) error {
			return c.Annotate(context.Background(), aidFixture, AnnotateInput{TransactionEvent: &TransactionEvent{EventType: "CHARGEBACK", Reason: pan}})
		},
	} {
		s := &stub{handler: respond(200, okAssessment)}
		err := call(stubClient(t, s))
		e := asError(err)
		if e == nil || e.Code != "bad-request" || e.Status != 0 || s.calls() != 0 || strings.Contains(err.Error(), "4242") || IsUnavailable(err) {
			t.Errorf("%s: %v (%d calls)", name, err, s.calls())
		}
	}
}

func TestCardFields(t *testing.T) {
	good := map[[2]string]Card{
		{"424242", "4242"}: {"424242", "4242"}, {"42424242", ""}: {"42424242", ""}, {"", "4242"}: {"", "4242"}, {"", ""}: {},
	}
	for in, want := range good {
		got, err := CardFields(in[0], in[1])
		if err != nil || got != want {
			t.Errorf("%v: %v %v", in, got, err)
		}
	}
	for _, in := range [][2]string{{"4242424242424242", ""}, {"42424", ""}, {"4242424", ""}, {"", "42424"}, {"", "424"}, {"42424a", ""}, {"", "٤٢٤٢"}, {"4242 4", ""}, {"", "4242424242424242"}} {
		c, err := CardFields(in[0], in[1])
		e := asError(err)
		if e == nil || e.Code != "bad-request" || e.Status != 0 || c != (Card{}) || strings.Contains(err.Error(), "424") {
			t.Errorf("%v: %v %v", in, c, err)
		}
	}
	// The fields fit TransactionData.
	card, _ := CardFields("424242", "4242")
	td := TransactionData{CardBin: card.BIN, CardLastFour: card.Last4}
	if !schema.TransactionData(td.wire()) {
		t.Fatal("card fields rejected by the schema")
	}
}

func TestAContextErrorIsMatchableAndTheCodeStaysNetworkError(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	hang := func(*http.Request) (*http.Response, error) { <-block; return nil, errors.New("x") }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := stubClient(t, &stub{handler: hang}).EraseAccount(ctx, AccountRef{AccountID: "u"})
	if e := asError(err); e == nil || e.Code != "network-error" || e.Status != 0 || !errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled: %v", err)
	}
	// The client's own timeout is a deadline.
	err = stubClient(t, &stub{handler: hang}, WithTimeout(50*time.Millisecond)).EraseAccount(context.Background(), AccountRef{AccountID: "u"})
	if e := asError(err); e == nil || e.Code != "network-error" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	// Another transport failure carries no cause (it could hold the request).
	err = stubClient(t, &stub{handler: func(*http.Request) (*http.Response, error) { return nil, errors.New("reset by peer") }}).EraseAccount(context.Background(), AccountRef{AccountID: "u"})
	if errors.Unwrap(err) != nil || strings.Contains(err.Error(), "reset") {
		t.Fatalf("%v", err)
	}
}

func TestFreeTextThatIsNotUTF8IsRefused(t *testing.T) {
	for name, in := range map[string]AssessmentInput{
		"token":  {Token: "a\xffb"},
		"agent":  {Express: true, UserAgent: "x\xc3"},
		"header": {Express: true, Headers: []string{"a: \xff"}},
	} {
		s := &stub{handler: respond(200, okAssessment)}
		if err := create(stubClient(t, s), in); !isInputError(err) || s.calls() != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}
