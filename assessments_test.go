package revokegpt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

const fullAssessment = `{
 "name": "assessments/` + aidFixture + `",
 "riskAnalysis": {"score": 0.25, "reasons": ["AUTOMATION", "DATACENTER_IP"], "challenge": "PASSED"},
 "tokenProperties": {"valid": false, "invalidReason": "EXPIRED", "createTime": "2026-11-08T10:00:00Z", "hostname": "shop.example", "action": "login", "cdata": "c_1"},
 "event": {"express": false, "expectedAction": "login"},
 "accountDefenderAssessment": {"labels": ["SUSPICIOUS_LOGIN_ACTIVITY", "SOMETHING_NEW"]},
 "requiresMfa": true,
 "accountVerification": {"endpoints": [{"requestToken": "rt_abc-DEF_1", "lastVerificationTime": "2026-11-01T00:00:00Z"}, {"lastVerificationTime": "2026-11-02T00:00:00Z"}], "latestVerificationResult": "SUCCESS_USER_VERIFIED"},
 "fraudPreventionAssessment": {"transactionRisk": 0.7, "cardTestingRisk": 0.1, "stolenInstrumentRisk": 0.2, "riskReasons": [{"reason": "HIGH_VALUE"}], "unscored": true, "cardTestingVerdict": {"risk": 0.1}, "stolenInstrumentVerdict": {"risk": 0.2}},
 "phoneFraudAssessment": {"smsTollFraudVerdict": {"risk": 0.4, "reasons": ["NEW_NUMBER"]}},
 "futureField": {"a": [1, 2, 3]}
}`

func TestTheTypedAssessment(t *testing.T) {
	s := &stub{handler: respond(200, fullAssessment)}
	a, err := stubClient(t, s).CreateAssessment(context.Background(), AssessmentInput{Token: "tok_abc", ExpectedAction: "login"})
	if err != nil {
		t.Fatal(err)
	}
	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	switch {
	case a.Name != "assessments/"+aidFixture,
		a.RiskAnalysis.Score != 0.25 || strings.Join(a.RiskAnalysis.Reasons, ",") != "AUTOMATION,DATACENTER_IP" || str(a.RiskAnalysis.Challenge) != "PASSED",
		a.TokenProperties.Valid || str(a.TokenProperties.InvalidReason) != "EXPIRED" || str(a.TokenProperties.Hostname) != "shop.example",
		str(a.TokenProperties.Action) != "login" || str(a.TokenProperties.CData) != "c_1" || a.TokenProperties.AndroidPackageName != nil,
		a.TokenProperties.CreateTime != "2026-11-08T10:00:00Z",
		a.AccountDefenderAssessment == nil || len(a.AccountDefenderAssessment.Labels) != 2 || a.RequiresMFA == nil || !*a.RequiresMFA,
		a.AccountVerification == nil || len(a.AccountVerification.Endpoints) != 2 || str(a.AccountVerification.Endpoints[0].RequestToken) != "rt_abc-DEF_1",
		a.AccountVerification.Endpoints[1].RequestToken != nil || str(a.AccountVerification.Endpoints[1].LastVerificationTime) != "2026-11-02T00:00:00Z",
		a.AccountVerification.LatestVerificationResult != "SUCCESS_USER_VERIFIED",
		a.FraudPreventionAssessment == nil || a.FraudPreventionAssessment.TransactionRisk != 0.7 || !a.FraudPreventionAssessment.Unscored || a.FraudPreventionAssessment.RiskReasons[0] != "HIGH_VALUE",
		a.PhoneFraudAssessment == nil || a.PhoneFraudAssessment.SMSTollFraudVerdict.Risk != 0.4 || a.PhoneFraudAssessment.SMSTollFraudVerdict.Unscored:
		t.Fatalf("%+v", a)
	}
	// Raw is the body as sent, unknown fields included.
	if string(a.Raw) != fullAssessment {
		t.Fatal("Raw differs from the body")
	}
	var m map[string]any
	if json.Unmarshal(a.Raw, &m) != nil || m["futureField"] == nil {
		t.Fatal("unknown field lost")
	}
	// Raw is a copy: the SDK's buffer is not shared with the caller.
	a.Raw[0] = 'X'
	b, _ := stubClient(t, &stub{handler: respond(200, fullAssessment)}).CreateAssessment(context.Background(), AssessmentInput{Token: "tok_abc"})
	if b.Raw[0] != '{' {
		t.Fatal("shared buffer")
	}
}

func TestOnlyASiteverifyEndpointServesTheOtherCalls(t *testing.T) {
	for _, ep := range []string{"https://api.revokegpt.test/v1/siteverify/", "https://api.revokegpt.test/v1", "https://api.revokegpt.test/v1/siteverify2"} {
		s := &stub{handler: respond(200, okAssessment)}
		c, err := New(fixtureSecret(t), ep, WithHTTPClient(&http.Client{Transport: s}))
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		_, e1 := c.CreateAssessment(ctx, AssessmentInput{Token: "t"})
		e2 := c.Annotate(ctx, aidFixture, AnnotateInput{})
		e3 := c.EraseAccount(ctx, AccountRef{AccountID: "u"})
		for _, e := range []error{e1, e2, e3} {
			if !isInputError(e) {
				t.Errorf("%s: %v", ep, e)
			}
		}
		// Verify works with any path.
		if s.calls() != 0 {
			t.Errorf("%s: a request was sent", ep)
		}
	}
	var nilClient *Client
	if _, err := nilClient.CreateAssessment(context.Background(), AssessmentInput{}); !isInputError(err) {
		t.Fatal(err)
	}
	var zero Client
	if err := zero.EraseAccount(context.Background(), AccountRef{AccountID: "u"}); !isInputError(err) {
		t.Fatal(err)
	}
}

func TestErrorsCarryTheirFieldsThroughWrapping(t *testing.T) {
	h := func(r *http.Request) (*http.Response, error) {
		resp, _ := respond(429, `{"error":{"code":"rate-limited","requestId":"req-9"}}`)(r)
		resp.Header.Set("Retry-After", "12")
		return resp, nil
	}
	err := stubClient(t, &stub{handler: h}).EraseAccount(context.Background(), AccountRef{AccountID: "u"})
	wrapped := fmt.Errorf("erase failed: %w", err)
	var e *Error
	if !errors.As(wrapped, &e) || e.Code != "rate-limited" || e.Status != 429 || e.RequestID != "req-9" || e.RetryAfterSeconds == nil || *e.RetryAfterSeconds != 12 {
		t.Fatalf("%+v", e)
	}
	if IsUnavailable(wrapped) {
		t.Fatal("429 is not unavailable")
	}
	// Two Retry-After lines are not one count of seconds.
	h2 := func(r *http.Request) (*http.Response, error) {
		resp, _ := respond(429, "")(r)
		resp.Header.Add("Retry-After", "5")
		resp.Header.Add("Retry-After", "7")
		return resp, nil
	}
	err = stubClient(t, &stub{handler: h2}).EraseAccount(context.Background(), AccountRef{AccountID: "u"})
	if e := asError(err); e == nil || e.RetryAfterSeconds != nil || e.Code != "internal-error" {
		t.Fatalf("%v", err)
	}
	// A typed nil *Error is safe to print and to ask.
	var nilErr *Error
	var asErr error = nilErr
	if asErr.Error() == "" || IsUnavailable(asErr) {
		t.Fatal("typed nil")
	}
	var nilInput *InputError
	if (error(nilInput)).Error() == "" {
		t.Fatal("typed nil input error")
	}
}

func TestBadRequestsAreArgumentErrorsAndSendNothing(t *testing.T) {
	big := math.Inf(1)
	nan := math.NaN()
	neg := -1.0
	huge := 1_000_001
	badTime := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := map[string]func(*Client) error{
		"invalid utf-8 account": func(c *Client) error { return c.EraseAccount(context.Background(), AccountRef{AccountID: "a\xffb"}) },
		"long account": func(c *Client) error {
			return c.EraseAccount(context.Background(), AccountRef{AccountID: strings.Repeat("é", 129)})
		},
		"both forms": func(c *Client) error {
			return c.EraseAccount(context.Background(), AccountRef{AccountID: "a", HashedAccountID: strings.Repeat("A", 43) + "="})
		},
		"inf value": func(c *Client) error {
			return create(c, AssessmentInput{TransactionData: &TransactionData{Value: &big}})
		},
		"nan value": func(c *Client) error {
			return create(c, AssessmentInput{TransactionData: &TransactionData{ShippingValue: &nan}})
		},
		"negative value": func(c *Client) error {
			return create(c, AssessmentInput{TransactionData: &TransactionData{Value: &neg}})
		},
		"huge quantity": func(c *Client) error {
			return create(c, AssessmentInput{TransactionData: &TransactionData{Items: []TransactionItem{{Quantity: &huge}}}})
		},
		"year 10000": func(c *Client) error {
			return create(c, AssessmentInput{UserInfo: &UserInfo{AccountRef: AccountRef{AccountID: "u"}, CreateAccountTime: &badTime}})
		},
		"empty user info": func(c *Client) error { return create(c, AssessmentInput{UserInfo: &UserInfo{}}) },
		"verification no account": func(c *Client) error {
			return create(c, AssessmentInput{AccountVerification: &AccountVerification{Endpoints: []Endpoint{{EmailAddress: "a@b.co"}}}})
		},
		"verification no endpoints": func(c *Client) error {
			return create(c, AssessmentInput{UserInfo: &UserInfo{AccountRef: AccountRef{AccountID: "u"}}, AccountVerification: &AccountVerification{}})
		},
		"verification 3 endpoints": func(c *Client) error {
			e := Endpoint{EmailAddress: "a@b.co"}
			return create(c, AssessmentInput{UserInfo: &UserInfo{AccountRef: AccountRef{AccountID: "u"}}, AccountVerification: &AccountVerification{Endpoints: []Endpoint{e, e, e}}})
		},
		"fraud prevention": func(c *Client) error { return create(c, AssessmentInput{FraudPrevention: "MAYBE"}) },
		"bad event type": func(c *Client) error {
			return c.Annotate(context.Background(), aidFixture, AnnotateInput{TransactionEvent: &TransactionEvent{EventType: "NOPE"}})
		},
		"bad event time": func(c *Client) error {
			return c.Annotate(context.Background(), aidFixture, AnnotateInput{TransactionEvent: &TransactionEvent{EventType: "REFUND", EventTime: "yesterday"}})
		},
		"two ids": func(c *Client) error {
			return create(c, AssessmentInput{UserInfo: &UserInfo{UserIDs: []UserID{{Email: "a@b.co", Username: "x"}}}})
		},
	}
	for name, f := range cases {
		s := &stub{handler: respond(200, okAssessment)}
		err := f(stubClient(t, s))
		if !isInputError(err) || s.calls() != 0 {
			t.Errorf("%s: %v (%d calls)", name, err, s.calls())
		}
	}
}

func create(c *Client, in AssessmentInput) error {
	_, err := c.CreateAssessment(context.Background(), in)
	return err
}

func TestTheWireFormOfAGoRequest(t *testing.T) {
	s := &stub{handler: respond(200, okAssessment)}
	yes, no := true, false
	v, q := 12.5, 2
	at := time.Date(2026, 11, 9, 10, 0, 0, 123_456_789, time.FixedZone("x", 3600))
	_, err := stubClient(t, s).CreateAssessment(context.Background(), AssessmentInput{
		Token: "tok", Express: false, Headers: []string{}, FraudPrevention: "ENABLED",
		UserInfo:            &UserInfo{AccountRef: AccountRef{HashedAccountID: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}, CreateAccountTime: &at, UserIDs: []UserID{{Email: "a@b.co"}}},
		AccountVerification: &AccountVerification{Endpoints: []Endpoint{{EmailAddress: "a@b.co"}}, LanguageCode: "en-US"},
		TransactionData: &TransactionData{
			PaymentMethod: "credit-card", Value: &v, User: &TransactionUser{EmailVerified: &no, PhoneVerified: &yes},
			Items: []TransactionItem{{Name: "n", Quantity: &q}}, Merchants: []TransactionUser{}, GatewayInfo: &GatewayInfo{Name: "stripe", AVSResponseCode: "Y"},
			ShippingAddress: &Address{Address: []string{"1 Main St"}, RegionCode: "US"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"accountVerification":{"endpoints":[{"emailAddress":"a@b.co"}],"languageCode":"en-US"},"event":{"fraudPrevention":"ENABLED","headers":[],` +
		`"token":"tok","transactionData":{"gatewayInfo":{"avsResponseCode":"Y","name":"stripe"},"items":[{"name":"n","quantity":2}],"merchants":[],` +
		`"paymentMethod":"credit-card","shippingAddress":{"address":["1 Main St"],"regionCode":"US"},"user":{"emailVerified":false,"phoneVerified":true},"value":12.5},` +
		`"userInfo":{"createAccountTime":"2026-11-09T09:00:00.123Z","hashedAccountId":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","userIds":[{"email":"a@b.co"}]}}}`
	if s.bodies[0] != want {
		t.Fatalf("\n got %s\nwant %s", s.bodies[0], want)
	}
	// An empty AnnotateInput is sent as {} (the edge refuses it; the SDK adds no check).
	s2 := &stub{handler: respond(200, "{}")}
	if err := stubClient(t, s2).Annotate(context.Background(), "assessments/"+aidFixture, AnnotateInput{}); err != nil || s2.bodies[0] != "{}" {
		t.Fatalf("%v %q", err, s2.bodies)
	}
}

func TestAHostileAssessmentBodyIsInvalidResponse(t *testing.T) {
	for name, body := range map[string]string{
		"deep":      `{"name":"x","a":` + strings.Repeat("[", 50000) + strings.Repeat("]", 50000) + `}`,
		"huge risk": strings.Replace(okAssessment, `"score":0.9`, `"score":1e999`, 1),
		"dupe name": strings.Replace(okAssessment, `"name":`, `"name":"assessments/short","name":`, 1),
		"BOM":       "\xef\xbb\xbf" + okAssessment,
		"extra":     okAssessment + " x",
	} {
		s := &stub{handler: respond(200, body)}
		a, err := stubClient(t, s).CreateAssessment(context.Background(), AssessmentInput{Token: "t"})
		e := asError(err)
		if name == "dupe name" {
			// The last duplicate wins, as in JSON.parse: a valid name.
			if err != nil || a == nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if e == nil || e.Code != "invalid-response" || e.Status != 200 || a != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTheSecretStaysOutOfEveryAssessmentPath(t *testing.T) {
	for name, h := range map[string]func(*http.Request) (*http.Response, error){
		"network": func(*http.Request) (*http.Response, error) { return nil, errors.New("reset") },
		"500":     respond(500, `{"error":{"code":"x","requestId":"r"}}`),
		"200":     respond(200, okAssessment),
		"bad":     respond(200, "nope"),
	} {
		s := &stub{handler: h}
		c := canaryClient(t, s)
		ctx := context.Background()
		_, e1 := c.CreateAssessment(ctx, AssessmentInput{Token: "t", UserInfo: &UserInfo{AccountRef: AccountRef{AccountID: "u"}}})
		e2 := c.Annotate(ctx, aidFixture, AnnotateInput{AccountRef: AccountRef{AccountID: "u"}})
		e3 := c.EraseAccount(ctx, AccountRef{AccountID: "u"})
		e4 := c.EraseAccount(ctx, AccountRef{})
		for _, e := range []error{e1, e2, e3, e4} {
			if e != nil {
				if got := leaks(fmt.Sprintf("%v %+v %#v %q", e, e, e, e)); got != "" {
					t.Errorf("%s: %q", name, got)
				}
			}
		}
		for i, r := range s.reqs {
			// The Authorization header has the canary secret; the URL and the other headers never do.
			if got := leaks(r.URL.String() + fmt.Sprint(r.Header["User-Agent"], r.Header["Content-Type"])); got != "" {
				t.Errorf("%s: request %d leaks %q", name, i, got)
			}
		}
	}
}
