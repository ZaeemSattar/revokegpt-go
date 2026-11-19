package schema

var (
	reasonCodes = []string{
		"AUTOMATION", "UNEXPECTED_ENVIRONMENT", "TOO_MUCH_TRAFFIC", "UNEXPECTED_USAGE_PATTERNS", "DATACENTER_IP",
		"ANONYMIZER", "INTEGRITY_FAILED", "LOW_CONFIDENCE_SCORE", "NETWORK_MISMATCH", "PLAN_RESTRICTED",
	}
	invalidReasons = []string{"MALFORMED", "EXPIRED", "DUPE", "MISSING", "UNEXPECTED_ACTION", "KEY_MISMATCH", "DOMAIN_MISMATCH"}
	verification   = []string{
		"RESULT_UNSPECIFIED", "SUCCESS_USER_VERIFIED", "ERROR_USER_NOT_VERIFIED", "ERROR_RECIPIENT_NOT_ALLOWED",
		"ERROR_RECIPIENT_ABUSE_LIMIT_EXHAUSTED", "ERROR_CUSTOMER_QUOTA_EXHAUSTED", "ERROR_SITE_ONBOARDING_INCOMPLETE",
		"ERROR_CRITICAL_INTERNAL",
	}
)

func isString(v any) bool { _, ok := v.(string); return ok }

func isTrue(v any) bool { b, ok := v.(bool); return ok && b }

func riskAnalysis(v any) bool {
	r, ok := v.(Object)
	if !ok || !risk(r["score"]) {
		return false
	}
	l, ok := list(r["reasons"], 0, -1)
	return ok && all(l, func(x any) bool { return oneOf(x, reasonCodes...) }) &&
		has(r, "challenge", func(v any) bool { return oneOf(v, "PASSED") })
}

func tokenProperties(v any) bool {
	t, ok := v.(Object)
	return ok && isBool(t["valid"]) && isString(t["createTime"]) &&
		has(t, "invalidReason", func(v any) bool { return oneOf(v, invalidReasons...) }) &&
		has(t, "hostname", isString) && has(t, "androidPackageName", isString) && has(t, "iosBundleId", isString) &&
		has(t, "action", isString) && has(t, "cdata", func(v any) bool { return matches(cdata, v) })
}

// VerificationEndpointHasToken says which member of the endpoint union a valid entry is: true for the one with
// a requestToken, false for the one with a lastVerificationTime. The first member that fits wins.
func VerificationEndpointHasToken(v any) bool {
	e, ok := v.(Object)
	if !ok {
		return false
	}
	t, present := e["requestToken"]
	s, isStr := t.(string)
	return present && isStr && ResponseToken(s)
}

func verificationEndpoint(v any) bool {
	e, ok := v.(Object)
	if !ok {
		return false
	}
	return VerificationEndpointHasToken(e) || isString(e["lastVerificationTime"])
}

func accountVerificationResponse(v any) bool {
	a, ok := v.(Object)
	if !ok {
		return false
	}
	l, ok := list(a["endpoints"], 0, -1)
	return ok && all(l, verificationEndpoint) && oneOf(a["latestVerificationResult"], verification...)
}

func openReasons(v any) bool {
	l, ok := list(v, 0, -1)
	return ok && all(l, func(x any) bool { return matches(openReason, x) })
}

func fraudPrevention(v any) bool {
	f, ok := v.(Object)
	if !ok {
		return false
	}
	reasons, ok := list(f["riskReasons"], 0, -1)
	if !ok || !all(reasons, func(x any) bool {
		m, ok := x.(Object)
		return ok && matches(openReason, m["reason"])
	}) {
		return false
	}
	for _, k := range []string{"cardTestingVerdict", "stolenInstrumentVerdict"} {
		m, ok := f[k].(Object)
		if !ok || !risk(m["risk"]) {
			return false
		}
	}
	return risk(f["transactionRisk"]) && risk(f["cardTestingRisk"]) && risk(f["stolenInstrumentRisk"]) &&
		has(f, "unscored", isTrue)
}

func phoneFraud(v any) bool {
	p, ok := v.(Object)
	if !ok {
		return false
	}
	s, ok := p["smsTollFraudVerdict"].(Object)
	return ok && risk(s["risk"]) && has(s, "unscored", isTrue) && openReasons(s["reasons"])
}

// Assessment reports whether v is a valid assessment response (a looseObject: unknown fields are kept).
func Assessment(v any) bool {
	o, ok := v.(Object)
	if !ok || !matches(assessmentName, o["name"]) || !riskAnalysis(o["riskAnalysis"]) || !tokenProperties(o["tokenProperties"]) {
		return false
	}
	event, ok := o["event"].(Object)
	if !ok || !isBool(event["express"]) || !has(event, "expectedAction", isString) {
		return false
	}
	if d, present := o["accountDefenderAssessment"]; present {
		m, ok := d.(Object)
		if !ok {
			return false
		}
		labels, ok := list(m["labels"], 0, -1)
		if !ok || !all(labels, func(x any) bool { return str(x, 0, 64) }) {
			return false
		}
	}
	return has(o, "requiresMfa", isBool) &&
		has(o, "accountVerification", accountVerificationResponse) &&
		has(o, "fraudPreventionAssessment", fraudPrevention) &&
		has(o, "phoneFraudAssessment", phoneFraud)
}
