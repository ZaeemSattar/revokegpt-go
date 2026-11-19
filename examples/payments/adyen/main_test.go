package main

import (
	"context"
	"strings"
	"testing"

	"github.com/ZaeemSattar/revokegpt-go/examples/internal/edgetest"
)

type fakeAdyen struct{ res Response }

func (g fakeAdyen) Authorise(context.Context, string, float64, string) (Response, error) {
	return g.res, nil
}

var order = Order{ID: "order-1", Currency: "USD", Token: "tok_abc", BIN: "424242", Last4: "4242", Amount: 59.9}

func TestRiskBands(t *testing.T) {
	for _, tc := range []struct {
		extra string
		want  string
		calls int
	}{
		{edgetest.Fraud(0.1, false), "authorised", 1}, {edgetest.Fraud(0.39, false), "authorised", 1}, {edgetest.Fraud(0.4, false), "step-up", 0},
		{edgetest.Fraud(0.69, false), "step-up", 0}, {edgetest.Fraud(0.7, false), "blocked", 0}, {edgetest.Fraud(0.1, true), "step-up", 0}, {"", "step-up", 0},
	} {
		e, rg := edgetest.New(t, tc.extra)
		got, err := AuthoriseWithScreening(context.Background(), rg, fakeAdyen{Response{ResultCode: "Authorised"}}, order)
		if err != nil || got != tc.want {
			t.Fatalf("%s: %q %v", tc.extra, got, err)
		}
		if len(e.Annotated) != tc.calls {
			t.Fatalf("%s: %d annotations", tc.extra, len(e.Annotated))
		}
	}
}

func TestOnlyTheBinAndLastFourAreSentAndTheOutcomeIsAnnotated(t *testing.T) {
	e, rg := edgetest.New(t, edgetest.Fraud(0.1, false))
	if _, err := AuthoriseWithScreening(context.Background(), rg, fakeAdyen{Response{ResultCode: "Refused", RefusalReason: "do_not_honor"}}, order); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.Requests[0], `"cardLastFour":"4242"`) || strings.Contains(e.Requests[0], "4242424242424242") {
		t.Fatalf("%s", e.Requests[0])
	}
	if len(e.Annotated) != 1 || !strings.Contains(e.Annotated[0], `"TRANSACTION_DECLINED"`) || !strings.Contains(e.Annotated[0], `"AUTHORIZATION_DECLINE"`) || !strings.Contains(e.Annotated[0], `"reason":"do_not_honor"`) {
		t.Fatalf("%v", e.Annotated)
	}
}

func TestACardNumberIsRefusedBeforeAnyRequest(t *testing.T) {
	e, rg := edgetest.New(t, edgetest.Fraud(0.1, false))
	if _, err := AuthoriseWithScreening(context.Background(), rg, fakeAdyen{Response{ResultCode: "Authorised"}}, Order{ID: "o", Currency: "USD", Token: "t", BIN: "4242424242424242", Last4: "4242"}); err == nil || strings.Contains(err.Error(), "4242") {
		t.Fatalf("%v", err)
	}
	if len(e.Requests) != 0 {
		t.Fatal("a request was sent")
	}
}

func TestChargebackFraud(t *testing.T) {
	e, rg := edgetest.New(t, "")
	if err := OnChargebackFraud(context.Background(), rg, "assessments/"+edgetest.AID); err != nil {
		t.Fatal(err)
	}
	if len(e.Annotated) != 1 || !strings.Contains(e.Annotated[0], `"CHARGEBACK_FRAUD"`) {
		t.Fatal(e.Annotated)
	}
}
