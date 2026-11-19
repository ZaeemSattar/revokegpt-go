// Command sms gates an SMS on the SMS toll-fraud verdict. RevokeGPT never sends the message; you do. Fictitious
// numbers only (Ofcom drama range).
package main

import (
	"context"
	"fmt"
	"os"

	revokegpt "github.com/ZaeemSattar/revokegpt-go"
)

// sendBelow: send only below this risk. An unscored verdict (every risk 0.5) is not a pass.
const sendBelow = 0.4

// Sender sends the message.
type Sender interface {
	Send(ctx context.Context, to, body string) error
}

// SendCodeIfSafe returns "sent" or "withheld".
func SendCodeIfSafe(ctx context.Context, rg *revokegpt.Client, sms Sender, token, phoneNumber, code string) (string, error) {
	a, err := rg.CreateAssessment(ctx, revokegpt.AssessmentInput{
		Token: token, ExpectedAction: "send_sms", FraudPrevention: "ENABLED",
		UserInfo: &revokegpt.UserInfo{UserIDs: []revokegpt.UserID{{PhoneNumber: phoneNumber}}},
	})
	if err != nil {
		return "", err
	}
	// No verdict, or an unscored one: do not send.
	p := a.PhoneFraudAssessment
	if p == nil || p.SMSTollFraudVerdict.Unscored || p.SMSTollFraudVerdict.Risk >= sendBelow {
		return "withheld", nil
	}
	if err := sms.Send(ctx, phoneNumber, "Your code is "+code); err != nil {
		return "", err
	}
	return "sent", nil
}

func main() {
	if _, err := revokegpt.New(os.Getenv("REVOKEGPT_SECRET"), os.Getenv("REVOKEGPT_ENDPOINT")); err != nil {
		fmt.Println("set REVOKEGPT_SECRET and REVOKEGPT_ENDPOINT, then call SendCodeIfSafe with phone number +447700900123")
	}
}
