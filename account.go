package revokegpt

import (
	"encoding/json"
	"github.com/ZaeemSattar/revokegpt-go/internal/schema"
	"strconv"
)

// This file builds the typed Assessment from a body that schema.Assessment accepted, so every assertion below
// holds.

func asObj(v any) map[string]any { m, _ := v.(map[string]any); return m }

func optStr(m map[string]any, key string) *string {
	if s, ok := m[key].(string); ok {
		return &s
	}
	return nil
}

func strList(v any) []string {
	l, _ := v.([]any)
	out := make([]string, len(l))
	for i, x := range l {
		out[i], _ = x.(string)
	}
	return out
}

func f64(v any) float64 {
	n, _ := v.(json.Number)
	f, _ := strconv.ParseFloat(n.String(), 64)
	return f
}

func newAssessment(o map[string]any, body []byte) *Assessment {
	a := &Assessment{Name: o["name"].(string), Raw: append(json.RawMessage(nil), body...)}
	r := asObj(o["riskAnalysis"])
	a.RiskAnalysis = RiskAnalysis{Score: f64(r["score"]), Reasons: strList(r["reasons"]), Challenge: optStr(r, "challenge")}
	t := asObj(o["tokenProperties"])
	a.TokenProperties = TokenProperties{
		Valid: t["valid"].(bool), CreateTime: t["createTime"].(string), InvalidReason: optStr(t, "invalidReason"),
		Hostname: optStr(t, "hostname"), AndroidPackageName: optStr(t, "androidPackageName"),
		IOSBundleID: optStr(t, "iosBundleId"), Action: optStr(t, "action"), CData: optStr(t, "cdata"),
	}
	if d, ok := o["accountDefenderAssessment"]; ok {
		a.AccountDefenderAssessment = &AccountDefenderAssessment{Labels: strList(asObj(d)["labels"])}
	}
	if b, ok := o["requiresMfa"].(bool); ok {
		a.RequiresMFA = &b
	}
	if v, ok := o["accountVerification"]; ok {
		m := asObj(v)
		res := &AccountVerificationResult{Endpoints: []VerificationEndpointResult{}, LatestVerificationResult: m["latestVerificationResult"].(string)}
		for _, e := range m["endpoints"].([]any) {
			em := asObj(e)
			// A union: the first member that fits wins (a valid requestToken), otherwise the second.
			if tok, ok := em["requestToken"].(string); ok && schema.ResponseToken(tok) {
				res.Endpoints = append(res.Endpoints, VerificationEndpointResult{RequestToken: &tok, LastVerificationTime: optStr(em, "lastVerificationTime")})
			} else {
				res.Endpoints = append(res.Endpoints, VerificationEndpointResult{LastVerificationTime: optStr(em, "lastVerificationTime")})
			}
		}
		a.AccountVerification = res
	}
	if v, ok := o["fraudPreventionAssessment"]; ok {
		m := asObj(v)
		f := &FraudPreventionAssessment{
			TransactionRisk: f64(m["transactionRisk"]), CardTestingRisk: f64(m["cardTestingRisk"]),
			StolenInstrumentRisk: f64(m["stolenInstrumentRisk"]), RiskReasons: []string{}, Unscored: m["unscored"] == true,
		}
		for _, x := range m["riskReasons"].([]any) {
			f.RiskReasons = append(f.RiskReasons, asObj(x)["reason"].(string))
		}
		a.FraudPreventionAssessment = f
	}
	if v, ok := o["phoneFraudAssessment"]; ok {
		s := asObj(asObj(v)["smsTollFraudVerdict"])
		a.PhoneFraudAssessment = &PhoneFraudAssessment{SMSTollFraudVerdict{Risk: f64(s["risk"]), Reasons: strList(s["reasons"]), Unscored: s["unscored"] == true}}
	}
	return a
}
