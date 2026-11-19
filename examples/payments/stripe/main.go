// Command stripe screens a card payment with RevokeGPT around a Stripe-style charge. Local minimal types: no
// gateway SDK is imported. Test card data only (4242...). Card data is never logged.
//
// Stripe: card.last4 is on the PaymentMethod's card hash. That hash has no IIN/BIN field (it has brand, country,
// funding, fingerprint, last4, ...), so this example sends the last four only and the service scores what it has.
// If your own card form exposes the BIN, pass it as Card.IIN. Verified 2026-11-15 against
// https://docs.stripe.com/api/payment_methods/object (card.last4; no BIN field). The decline code goes in
// TransactionEvent.Reason.
package main

import (
	"context"
	"fmt"
	"os"

	revokegpt "github.com/ZaeemSattar/revokegpt-go"
)

const (
	block  = 0.7 // block at or above this risk
	stepUp = 0.4 // ask for more proof at or above this risk; an unscored answer (0.5) lands here
)

// Card is the card hash of a Stripe PaymentMethod.
type Card struct{ Last4, IIN string }

// ChargeResult is what the gateway answered.
type ChargeResult struct {
	OK          bool
	DeclineCode string
}

// Gateway is the part of a Stripe client this example uses.
type Gateway interface {
	RetrieveCard(ctx context.Context, paymentMethodID string) (Card, error)
	Charge(ctx context.Context, paymentMethodID string, amount float64, currency string) (ChargeResult, error)
}

// Order is what the shop knows about the purchase.
type Order struct {
	ID, Currency, PaymentMethodID, Token string
	Amount                               float64
}

// ChargeWithScreening returns "paid", "declined", "blocked" or "step-up".
func ChargeWithScreening(ctx context.Context, rg *revokegpt.Client, gw Gateway, o Order) (string, error) {
	card, err := gw.RetrieveCard(ctx, o.PaymentMethodID)
	if err != nil {
		return "", err
	}
	// 1. Assess before the charge. CardFields refuses anything that is not a BIN and a last four.
	fields, err := revokegpt.CardFields(card.IIN, card.Last4)
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

	// 2. Charge, then tell RevokeGPT what the gateway answered, with the gateway's own code.
	res, err := gw.Charge(ctx, o.PaymentMethodID, o.Amount, o.Currency)
	if err != nil {
		return "", err
	}
	in := revokegpt.AnnotateInput{Reasons: []string{"TRANSACTION_ACCEPTED"}, TransactionEvent: &revokegpt.TransactionEvent{EventType: "AUTHORIZATION"}}
	if !res.OK {
		in = revokegpt.AnnotateInput{Reasons: []string{"TRANSACTION_DECLINED"}, TransactionEvent: &revokegpt.TransactionEvent{EventType: "AUTHORIZATION_DECLINE", Reason: res.DeclineCode}}
	}
	// An annotation failure must never fail the payment.
	_ = rg.Annotate(ctx, a.Name, in)
	if res.OK {
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
		fmt.Println("set REVOKEGPT_SECRET and REVOKEGPT_ENDPOINT, then call ChargeWithScreening from your handler")
	}
}
