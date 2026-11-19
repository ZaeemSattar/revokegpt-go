// Command braintree screens a card payment with RevokeGPT around a Braintree-style sale. Local minimal types.
// Test card data only (4242...). Card data is never logged.
//
// Braintree: a credit card has bin (first 6 digits) and last_4; a declined transaction has
// processor_response_code. Verified 2026-11-15 against
// https://developer.paypal.com/braintree/docs/reference/response/credit-card and
// https://developer.paypal.com/braintree/docs/reference/response/transaction/.
package main

import (
	"context"
	"fmt"
	"os"

	revokegpt "github.com/ZaeemSattar/revokegpt-go"
)

const (
	block  = 0.7
	stepUp = 0.4
)

// CreditCard is the card of a Braintree payment method.
type CreditCard struct{ BIN, Last4 string }

// SaleResult is what the gateway answered.
type SaleResult struct {
	Success               bool
	ProcessorResponseCode string
}

// Braintree is the part of a Braintree client this example uses.
type Braintree interface {
	FindPaymentMethod(ctx context.Context, token string) (CreditCard, error)
	Sale(ctx context.Context, paymentMethodToken string, amount float64) (SaleResult, error)
}

// Order is what the shop knows about the purchase.
type Order struct {
	ID, Currency, PaymentMethodToken, Token string
	Amount                                  float64
}

// SaleWithScreening returns "paid", "declined", "blocked" or "step-up".
func SaleWithScreening(ctx context.Context, rg *revokegpt.Client, bt Braintree, o Order) (string, error) {
	card, err := bt.FindPaymentMethod(ctx, o.PaymentMethodToken)
	if err != nil {
		return "", err
	}
	fields, err := revokegpt.CardFields(card.BIN, card.Last4) // anything but a BIN and a last four is refused
	if err != nil {
		return "", err
	}
	amount := o.Amount
	a, err := rg.CreateAssessment(ctx, revokegpt.AssessmentInput{
		Token: o.Token, ExpectedAction: "checkout", FraudPrevention: "ENABLED",
		TransactionData: &revokegpt.TransactionData{
			TransactionID: o.ID, PaymentMethod: "credit-card", CardBin: fields.BIN, CardLastFour: fields.Last4,
			CurrencyCode: o.Currency, Value: &amount,
		},
	})
	if err != nil {
		return "", err
	}
	risk := 0.5 // no verdict, or an unscored one: step up
	if f := a.FraudPreventionAssessment; f != nil && !f.Unscored {
		risk = f.TransactionRisk
	}
	if risk >= block {
		return "blocked", nil
	}
	if risk >= stepUp {
		return "step-up", nil
	}
	res, err := bt.Sale(ctx, o.PaymentMethodToken, o.Amount)
	if err != nil {
		return "", err
	}
	in := revokegpt.AnnotateInput{Reasons: []string{"TRANSACTION_ACCEPTED"}, TransactionEvent: &revokegpt.TransactionEvent{EventType: "AUTHORIZATION"}}
	if !res.Success {
		in = revokegpt.AnnotateInput{Reasons: []string{"TRANSACTION_DECLINED"}, TransactionEvent: &revokegpt.TransactionEvent{EventType: "AUTHORIZATION_DECLINE", Reason: res.ProcessorResponseCode}}
	}
	_ = rg.Annotate(ctx, a.Name, in) // an annotation failure must never fail the payment
	if res.Success {
		return "paid", nil
	}
	return "declined", nil
}

// OnChargebackFraud is for a dispute webhook of a payment you screened (within 30 days of the assessment).
func OnChargebackFraud(ctx context.Context, rg *revokegpt.Client, assessmentName string) error {
	return rg.Annotate(ctx, assessmentName, revokegpt.AnnotateInput{
		Annotation: "FRAUDULENT", Reasons: []string{"CHARGEBACK_FRAUD"},
		TransactionEvent: &revokegpt.TransactionEvent{EventType: "CHARGEBACK"},
	})
}

func main() {
	if _, err := revokegpt.New(os.Getenv("REVOKEGPT_SECRET"), os.Getenv("REVOKEGPT_ENDPOINT")); err != nil {
		fmt.Println("set REVOKEGPT_SECRET and REVOKEGPT_ENDPOINT, then call SaleWithScreening from your handler")
	}
}
