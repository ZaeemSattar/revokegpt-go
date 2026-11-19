package schema

// The closed enums of the request side.
var (
	annotateReasons = []string{
		"CHARGEBACK", "CHARGEBACK_FRAUD", "CHARGEBACK_DISPUTE", "REFUND", "REFUND_FRAUD", "TRANSACTION_ACCEPTED",
		"TRANSACTION_DECLINED", "PAYMENT_HEURISTICS", "INITIATED_TWO_FACTOR", "PASSED_TWO_FACTOR", "FAILED_TWO_FACTOR",
		"CORRECT_PASSWORD", "INCORRECT_PASSWORD", "SOCIAL_SPAM", "PAYMENT_FRAUD",
	}
	transactionEventTypes = []string{
		"TRANSACTION_EVENT_TYPE_UNSPECIFIED", "MERCHANT_APPROVE", "MERCHANT_DENY", "MANUAL_REVIEW", "AUTHORIZATION",
		"AUTHORIZATION_DECLINE", "PAYMENT_CAPTURE", "PAYMENT_CAPTURE_DECLINE", "CANCEL", "CHARGEBACK_INQUIRY",
		"CHARGEBACK_ALERT", "FRAUD_NOTIFICATION", "CHARGEBACK", "CHARGEBACK_REPRESENTMENT", "CHARGEBACK_REVERSE",
		"REFUND_REQUEST", "REFUND_DECLINE", "REFUND", "REFUND_REVERSE",
	}
	fraudPreventionValues = []string{"FRAUD_PREVENTION_UNSPECIFIED", "ENABLED", "DISABLED"}
)

// AccountIDMaxBytes is the most UTF-8 bytes of an account id.
const AccountIDMaxBytes = 256

// FraudPrevention reports whether v is one of the closed fraudPrevention values.
func FraudPrevention(v string) bool { return oneOf(v, fraudPreventionValues...) }

func accountID(v any) bool {
	s, ok := v.(string)
	return ok && str(s, 1, -1) && len(s) <= AccountIDMaxBytes
}

func hashedAccount(v any) bool { return matches(hashedAccountID, v) }

func userID(v any) bool {
	u, ok := keysOK(v, "email", "phoneNumber", "username")
	if !ok || len(u) != 1 { // exactly one of the three
		return false
	}
	return has(u, "email", func(v any) bool { return str(v, 1, 320) }) &&
		has(u, "phoneNumber", func(v any) bool { return str(v, 1, 32) }) &&
		has(u, "username", func(v any) bool { return str(v, 1, 256) })
}

// UserInfo is `event.userInfo` (section 15), with the SDK rule that it names an account or carries userIds.
func UserInfo(v any) bool {
	d, ok := keysOK(v, "accountId", "hashedAccountId", "createAccountTime", "userIds")
	if !ok {
		return false
	}
	_, a := d["accountId"]
	_, h := d["hashedAccountId"]
	_, u := d["userIds"]
	return has(d, "accountId", accountID) && has(d, "hashedAccountId", hashedAccount) &&
		has(d, "createAccountTime", dateTimeValue) &&
		has(d, "userIds", func(v any) bool {
			l, ok := list(v, 0, 10)
			return ok && all(l, userID)
		}) && !(a && h) && (a || h || u)
}

// emailAddress is `^[^@ \t\r\n]{1,64}@[^@ \t\r\n]{1,189}$` and at most 254 characters.
func emailAddress(v any) bool {
	s, ok := v.(string)
	if !ok || !str(s, 1, 254) {
		return false
	}
	at := -1
	for i, r := range s {
		switch r {
		case ' ', '\t', '\r', '\n':
			return false
		case '@':
			if at >= 0 {
				return false
			}
			at = i
		}
	}
	if at < 0 {
		return false
	}
	return str(s[:at], 1, 64) && str(s[at+1:], 1, 189)
}

func endpoint(v any) bool {
	e, ok := v.(Object)
	if !ok || len(e) != 1 {
		return false
	}
	if a, ok := e["emailAddress"]; ok {
		return emailAddress(a)
	}
	if p, ok := e["phoneNumber"]; ok {
		return matches(e164, p)
	}
	return false
}

// AccountVerification is the top-level `accountVerification` of a request (section 17).
func AccountVerification(v any) bool {
	d, ok := keysOK(v, "endpoints", "languageCode")
	if !ok {
		return false
	}
	eps, present := d["endpoints"]
	if !present {
		return false
	}
	l, ok := list(eps, 1, 2)
	return ok && all(l, endpoint) &&
		has(d, "languageCode", func(v any) bool { return str(v, 0, 35) && matches(languageCode, v) })
}

func transactionEvent(v any) bool {
	e, ok := keysOK(v, "eventType", "reason", "value", "eventTime")
	return ok && oneOf(e["eventType"], transactionEventTypes...) &&
		has(e, "reason", func(v any) bool { return str(v, 0, 64) }) &&
		has(e, "value", money) && has(e, "eventTime", dateTimeValue)
}

// Annotate is the body of `:annotate` (section 14). An empty body is valid here: the edge answers bad-request.
func Annotate(v any) bool {
	d, ok := keysOK(v, "annotation", "reasons", "accountId", "hashedAccountId", "transactionEvent")
	if !ok {
		return false
	}
	_, a := d["accountId"]
	_, h := d["hashedAccountId"]
	return has(d, "annotation", func(v any) bool { return oneOf(v, "LEGITIMATE", "FRAUDULENT") }) &&
		has(d, "reasons", func(v any) bool {
			l, ok := list(v, 0, 14)
			return ok && all(l, func(r any) bool { return oneOf(r, annotateReasons...) })
		}) &&
		has(d, "accountId", accountID) && has(d, "hashedAccountId", hashedAccount) &&
		has(d, "transactionEvent", transactionEvent) && !(a && h)
}

// Erase is the body of `accounts:erase` (section 15): exactly one of accountId and hashedAccountId.
func Erase(v any) bool {
	d, ok := keysOK(v, "accountId", "hashedAccountId")
	return ok && len(d) == 1 && has(d, "accountId", accountID) && has(d, "hashedAccountId", hashedAccount)
}

// AID reports whether s is an assessment id, bare or as assessments/<aid>, and returns the bare id.
func AID(s string) (string, bool) {
	if !aid.MatchString(s) {
		return "", false
	}
	const prefix = "assessments/"
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return s, true
}

func address(v any) bool {
	a, ok := keysOK(v, "recipient", "address", "locality", "administrativeArea", "regionCode", "postalCode")
	return ok &&
		has(a, "recipient", func(v any) bool { return str(v, 0, 100) }) &&
		has(a, "address", func(v any) bool {
			l, ok := list(v, 0, 4)
			return ok && all(l, func(x any) bool { return str(x, 0, 100) })
		}) &&
		has(a, "locality", func(v any) bool { return str(v, 0, 100) }) &&
		has(a, "administrativeArea", func(v any) bool { return str(v, 0, 100) }) &&
		has(a, "regionCode", func(v any) bool { return matches(region, v) }) &&
		has(a, "postalCode", func(v any) bool { return str(v, 0, 16) })
}

func isBool(v any) bool { _, ok := v.(bool); return ok }

func transactionUser(v any) bool {
	u, ok := keysOK(v, "accountId", "creationMs", "email", "emailVerified", "phoneNumber", "phoneVerified")
	return ok &&
		has(u, "accountId", func(v any) bool { return str(v, 0, 256) }) &&
		has(u, "creationMs", func(v any) bool { return matches(creationMs, v) }) &&
		has(u, "email", func(v any) bool { return str(v, 0, 320) }) &&
		has(u, "emailVerified", isBool) &&
		has(u, "phoneNumber", func(v any) bool { return str(v, 0, 32) }) &&
		has(u, "phoneVerified", isBool)
}

func transactionItem(v any) bool {
	i, ok := keysOK(v, "name", "value", "quantity", "merchantAccountId")
	return ok &&
		has(i, "name", func(v any) bool { return str(v, 0, 100) }) &&
		has(i, "value", money) &&
		has(i, "quantity", func(v any) bool { f, _ := number(v); return isInt(v) && f >= 0 && f <= 1_000_000 }) &&
		has(i, "merchantAccountId", func(v any) bool { return str(v, 0, 128) })
}

func gatewayInfo(v any) bool {
	g, ok := keysOK(v, "name", "gatewayResponseCode", "avsResponseCode", "cvvResponseCode")
	return ok &&
		has(g, "name", func(v any) bool { return matches(gatewayName, v) }) &&
		has(g, "gatewayResponseCode", func(v any) bool { return str(v, 0, 64) }) &&
		has(g, "avsResponseCode", func(v any) bool { return str(v, 0, 8) }) &&
		has(g, "cvvResponseCode", func(v any) bool { return str(v, 0, 8) })
}

// TransactionData is `event.transactionData` (section 20) against its schema: unknown keys, a BIN that is not 6
// or 8 digits and the other limits are refused. The card-number (PAN) scan of section 20.1 is NOT here: the
// payments part of the SDK runs it over every string before this check.
func TransactionData(v any) bool {
	d, ok := keysOK(v, "transactionId", "paymentMethod", "cardBin", "cardLastFour", "currencyCode", "value",
		"shippingValue", "shippingAddress", "billingAddress", "user", "merchants", "items", "gatewayInfo")
	return ok &&
		has(d, "transactionId", func(v any) bool { return str(v, 0, 128) }) &&
		has(d, "paymentMethod", func(v any) bool { return matches(paymentMethod, v) }) &&
		has(d, "cardBin", func(v any) bool { return matches(cardBin, v) }) &&
		has(d, "cardLastFour", func(v any) bool { return matches(lastFour, v) }) &&
		has(d, "currencyCode", func(v any) bool { return matches(currency, v) }) &&
		has(d, "value", money) && has(d, "shippingValue", money) &&
		has(d, "shippingAddress", address) && has(d, "billingAddress", address) &&
		has(d, "user", transactionUser) &&
		has(d, "merchants", func(v any) bool {
			l, ok := list(v, 0, 5)
			return ok && all(l, transactionUser)
		}) &&
		has(d, "items", func(v any) bool {
			l, ok := list(v, 0, 20)
			return ok && all(l, transactionItem)
		}) &&
		has(d, "gatewayInfo", gatewayInfo)
}
