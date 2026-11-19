// Command adyen screens a card payment with RevokeGPT around an Adyen-style authorisation. Local minimal types.
// Test card data only (4242...). Card data is never logged.
//
// Adyen: the /payments response carries additionalData.cardSummary (last four) and, once you enable "Card bin
// details" under Developers > Additional data in the Customer Area, additionalData.cardBin; a refusal carries
// refusalReason. They arrive after authorisation, so for a first attempt take the BIN and last four from the card
// form's own non-sensitive fields (a tokenised field exposes them) and use these response fields when you
// annotate or retry. Verified 2026-11-15 against
// https://docs.adyen.com/api-explorer/Checkout/latest/post/payments; the format of cardBin is not specified
// there, so CardFields validates it (6 or 8 digits).
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

// Response is the part of an Adyen /payments answer this example reads.
type Response struct {
	ResultCode    string // "Authorised", "Refused", "Error", ...
	RefusalReason string
	CardBin       string
	CardSummary   string
}

// Adyen is the part of an Adyen client this example uses.
type Adyen interface {
	Authorise(ctx context.Context, reference string, amount float64, currency string) (Response, error)
}

// Order is what the shop knows about the purchase. BIN and Last4 come from the card form's tokenised,
// non-sensitive fields.
type Order struct {
	ID, Currency, Token, BIN, Last4 string
	Amount                          float64
}

// AuthoriseWithScreening returns "authorised", "refused", "blocked" or "step-up".
func AuthoriseWithScreening(ctx context.Context, rg *revokegpt.Client, ad Adyen, o Order) (string, error) {
	fields, err := revokegpt.CardFields(o.BIN, o.Last4) // anything but a BIN and a last four is refused
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
	res, err := ad.Authorise(ctx, o.ID, o.Amount, o.Currency)
	if err != nil {
		return "", err
	}
	ok := res.ResultCode == "Authorised"
	in := revokegpt.AnnotateInput{Reasons: []string{"TRANSACTION_ACCEPTED"}, TransactionEvent: &revokegpt.TransactionEvent{EventType: "AUTHORIZATION"}}
	if !ok {
		in = revokegpt.AnnotateInput{Reasons: []string{"TRANSACTION_DECLINED"}, TransactionEvent: &revokegpt.TransactionEvent{EventType: "AUTHORIZATION_DECLINE", Reason: res.RefusalReason}}
	}
	_ = rg.Annotate(ctx, a.Name, in) // an annotation failure must never fail the payment
	if ok {
		return "authorised", nil
	}
	return "refused", nil
}

// ResponseCardFields maps Adyen's response fields to the card fields (for an annotation-time or retry check).
func ResponseCardFields(res Response) (revokegpt.Card, error) {
	return revokegpt.CardFields(res.CardBin, res.CardSummary)
}

// OnChargebackFraud is for a chargeback notification of a payment you screened (within 30 days of the assessment).
func OnChargebackFraud(ctx context.Context, rg *revokegpt.Client, assessmentName string) error {
	return rg.Annotate(ctx, assessmentName, revokegpt.AnnotateInput{
		Annotation: "FRAUDULENT", Reasons: []string{"CHARGEBACK_FRAUD"},
		TransactionEvent: &revokegpt.TransactionEvent{EventType: "CHARGEBACK"},
	})
}

func main() {
	if _, err := revokegpt.New(os.Getenv("REVOKEGPT_SECRET"), os.Getenv("REVOKEGPT_ENDPOINT")); err != nil {
		fmt.Println("set REVOKEGPT_SECRET and REVOKEGPT_ENDPOINT, then call AuthoriseWithScreening from your handler")
	}
}
