package revokegpt

import (
	"encoding/json"
	"time"
)

// Request types. A zero value is "not given": an empty string, a nil pointer, slice or map are left out of the
// request. (A slice you set to an empty, non-nil value is sent as an empty list.) The json tags are the wire
// names of the protocol; the SDK builds the request itself, field by field, and checks it against the schema
// before anything is sent. A bad value is an *InputError (it matches ErrInvalidInput), reported before any
// request is made, and its text never includes the value.

// AccountRef names an account with exactly one of AccountID (1 to 256 UTF-8 bytes) and HashedAccountID
// (canonical padded base64 of 32 bytes you hashed). Use one form for an account everywhere (assess, annotate,
// erase): the same account sent in the two forms gives two different hashes.
type AccountRef struct {
	AccountID       string `json:"accountId,omitempty"`
	HashedAccountID string `json:"hashedAccountId,omitempty"`
}

// UserID is one contact detail of UserInfo.UserIDs: exactly one of the three. With the site's smsTollFraud flag
// on, the first PhoneNumber is scored for SMS toll fraud (E.164). Nothing else here is stored or logged.
type UserID struct {
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Username    string `json:"username,omitempty"`
}

// UserInfo is event.userInfo: the account of a token assessment (not Express). Name it with the AccountRef
// (exactly one form), or pass only UserIDs.
type UserInfo struct {
	AccountRef
	// CreateAccountTime is when the account was created. At most 600 s before now makes the assessment an
	// account creation. It is sent as RFC 3339 UTC with milliseconds.
	CreateAccountTime *time.Time `json:"createAccountTime,omitempty"`
	UserIDs           []UserID   `json:"userIds,omitempty"`
}

// Endpoint is an address a verification code is sent to: exactly one of the two. SMS is not offered yet: the
// service answers 403 feature-disabled for a PhoneNumber.
type Endpoint struct {
	EmailAddress string `json:"emailAddress,omitempty"`
	PhoneNumber  string `json:"phoneNumber,omitempty"`
}

// AccountVerification asks for an email verification of the account in AssessmentInput.UserInfo (section 17).
// It needs a named account there. The response lists one request token per endpoint, in this order.
type AccountVerification struct {
	// Endpoints is one or two endpoints.
	Endpoints    []Endpoint `json:"endpoints"`
	LanguageCode string     `json:"languageCode,omitempty"`
}

// Address is a postal address of TransactionData.
type Address struct {
	Recipient          string   `json:"recipient,omitempty"`
	Address            []string `json:"address,omitempty"`
	Locality           string   `json:"locality,omitempty"`
	AdministrativeArea string   `json:"administrativeArea,omitempty"`
	// RegionCode is two upper-case letters.
	RegionCode string `json:"regionCode,omitempty"`
	PostalCode string `json:"postalCode,omitempty"`
}

// TransactionUser is a buyer or a merchant of TransactionData.
type TransactionUser struct {
	AccountID string `json:"accountId,omitempty"`
	// CreationMS is epoch milliseconds as a string of at most 13 digits.
	CreationMS    string `json:"creationMs,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"emailVerified,omitempty"`
	PhoneNumber   string `json:"phoneNumber,omitempty"`
	PhoneVerified *bool  `json:"phoneVerified,omitempty"`
}

// TransactionItem is one line of TransactionData.
type TransactionItem struct {
	Name              string   `json:"name,omitempty"`
	Value             *float64 `json:"value,omitempty"`
	Quantity          *int     `json:"quantity,omitempty"`
	MerchantAccountID string   `json:"merchantAccountId,omitempty"`
}

// GatewayInfo is what the payment gateway answered.
type GatewayInfo struct {
	// Name is lower case, 1 to 32 characters of a-z 0-9 _ -.
	Name                string `json:"name,omitempty"`
	GatewayResponseCode string `json:"gatewayResponseCode,omitempty"`
	AVSResponseCode     string `json:"avsResponseCode,omitempty"`
	CVVResponseCode     string `json:"cvvResponseCode,omitempty"`
}

// TransactionData is the payment to score, before you charge (section 20; token assessments only). Only the BIN
// (6 or 8 digits) and the last four digits of a card are accepted: there is no field for a card number, an
// expiry or a CVV.
type TransactionData struct {
	TransactionID string `json:"transactionId,omitempty"`
	// PaymentMethod is credit-card, debit-card, gift-card, processor-<name> or custom-<name>.
	PaymentMethod string `json:"paymentMethod,omitempty"`
	CardBin       string `json:"cardBin,omitempty"`
	CardLastFour  string `json:"cardLastFour,omitempty"`
	// CurrencyCode is ISO 4217, upper case.
	CurrencyCode    string            `json:"currencyCode,omitempty"`
	Value           *float64          `json:"value,omitempty"`
	ShippingValue   *float64          `json:"shippingValue,omitempty"`
	ShippingAddress *Address          `json:"shippingAddress,omitempty"`
	BillingAddress  *Address          `json:"billingAddress,omitempty"`
	User            *TransactionUser  `json:"user,omitempty"`
	Merchants       []TransactionUser `json:"merchants,omitempty"`
	Items           []TransactionItem `json:"items,omitempty"`
	GatewayInfo     *GatewayInfo      `json:"gatewayInfo,omitempty"`
}

// TransactionEvent is the outcome of a payment an assessment scored (Annotate). Reason is the gateway's own
// code.
type TransactionEvent struct {
	// EventType is one of the TRANSACTION_EVENT_TYPE values of the protocol, such as AUTHORIZATION_DECLINE.
	EventType string   `json:"eventType"`
	Reason    string   `json:"reason,omitempty"`
	Value     *float64 `json:"value,omitempty"`
	// EventTime is an RFC 3339 date-time with an offset, sent as you give it (a Go time.Time cannot keep the
	// spelling the service will hash and compare). Leave it empty to omit it.
	EventTime string `json:"eventTime,omitempty"`
}

// AssessmentInput is the request of CreateAssessment.
type AssessmentInput struct {
	// Token is the response token of a widget. Leave it empty for an Express assessment.
	Token          string `json:"token,omitempty"`
	ExpectedAction string `json:"expectedAction,omitempty"`
	// Express scores UserIPAddress, UserAgent and Headers alone, with no token.
	Express       bool     `json:"express,omitempty"`
	UserIPAddress string   `json:"userIpAddress,omitempty"`
	UserAgent     string   `json:"userAgent,omitempty"`
	Headers       []string `json:"headers,omitempty"`
	// UserInfo and AccountVerification are for account protection and email verification.
	UserInfo            *UserInfo            `json:"userInfo,omitempty"`
	AccountVerification *AccountVerification `json:"accountVerification,omitempty"`
	// TransactionData and FraudPrevention are for payments. FraudPrevention is FRAUD_PREVENTION_UNSPECIFIED,
	// ENABLED or DISABLED.
	TransactionData *TransactionData `json:"transactionData,omitempty"`
	FraudPrevention string           `json:"fraudPrevention,omitempty"`
}

// AnnotateInput is the request of Annotate: what happened after an assessment. An empty input is sent as it
// is, and the service refuses it (bad-request).
type AnnotateInput struct {
	// Annotation is LEGITIMATE or FRAUDULENT.
	Annotation string `json:"annotation,omitempty"`
	// Reasons are values such as CHARGEBACK_FRAUD or CORRECT_PASSWORD.
	Reasons []string `json:"reasons,omitempty"`
	// AccountRef is the account a password or two-factor outcome belongs to.
	AccountRef
	TransactionEvent *TransactionEvent `json:"transactionEvent,omitempty"`
}

// Response types. An optional field is a pointer: nil is "absent". Reason and label lists are open: tolerate
// values you do not know. Raw is the whole body of the answer, for open enums and for fields a newer service
// adds.

// Assessment is a parsed assessment.
type Assessment struct {
	// Name is assessments/<id>.
	Name                      string
	RiskAnalysis              RiskAnalysis
	TokenProperties           TokenProperties
	AccountDefenderAssessment *AccountDefenderAssessment
	RequiresMFA               *bool
	AccountVerification       *AccountVerificationResult
	FraudPreventionAssessment *FraudPreventionAssessment
	PhoneFraudAssessment      *PhoneFraudAssessment
	// Raw is the body exactly as the service sent it.
	Raw json.RawMessage
}

// RiskAnalysis is the score (0 to 1) and the reasons behind it.
type RiskAnalysis struct {
	Score   float64
	Reasons []string
	// Challenge is "PASSED" when the token was solved through a challenge, else nil.
	Challenge *string
}

// TokenProperties describes the token of a token assessment.
type TokenProperties struct {
	Valid      bool
	CreateTime string
	// InvalidReason says why the token is not valid, when it is not.
	InvalidReason      *string
	Hostname           *string
	AndroidPackageName *string
	IOSBundleID        *string
	Action             *string
	CData              *string
}

// AccountDefenderAssessment holds account labels from an open enum.
type AccountDefenderAssessment struct{ Labels []string }

// VerificationEndpointResult is one entry of AccountVerificationResult.Endpoints: a request token (to send the
// code with mfa/send) or the time of the last verification.
type VerificationEndpointResult struct {
	RequestToken         *string
	LastVerificationTime *string
}

// AccountVerificationResult has one endpoint entry per endpoint of the request, in order.
type AccountVerificationResult struct {
	Endpoints                []VerificationEndpointResult
	LatestVerificationResult string
}

// FraudPreventionAssessment is the payment verdict (section 20): risks from 0 to 1. Unscored is true when no
// score could be made.
type FraudPreventionAssessment struct {
	TransactionRisk      float64
	CardTestingRisk      float64
	StolenInstrumentRisk float64
	RiskReasons          []string
	Unscored             bool
}

// SMSTollFraudVerdict is the SMS toll fraud verdict of a phone number.
type SMSTollFraudVerdict struct {
	Risk     float64
	Reasons  []string
	Unscored bool
}

// PhoneFraudAssessment is the phone verdict of an assessment.
type PhoneFraudAssessment struct{ SMSTollFraudVerdict SMSTollFraudVerdict }
