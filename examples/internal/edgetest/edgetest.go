// Package edgetest is the stub edge the example tests share: an httptest server that answers an assessment
// (with the verdict a test gives it) and records every request. Test helper only.
package edgetest

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	revokegpt "github.com/ZaeemSattar/revokegpt-go"
)

// Secret is the published test secret of the protocol vectors.
const Secret = "rgsk_7Hq2LmZ9xK4a_Rb3Nf8Tw1Yc6Vg0Jp5Ds2Ek9Ux4Ih7Ma07q80x"

// AID is an assessment id.
const AID = "aB3_-aB3_-aB3_-aB3_-aB3_-aB3_-aB3_-aB3_-cD"

// Edge records what arrived.
type Edge struct {
	mu        sync.Mutex
	Requests  []string
	Annotated []string
}

// New starts the edge and returns a client for it. extra is JSON members (starting with a comma) added to the
// assessment answer.
func New(t *testing.T, extra string) (*Edge, *revokegpt.Client) {
	t.Helper()
	e := &Edge{}
	answer := `{"name":"assessments/` + AID + `","riskAnalysis":{"score":0.9,"reasons":[]},"tokenProperties":{"valid":true,"createTime":"2026-11-08T10:00:00Z"},"event":{"express":false}` + extra + `}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		defer e.mu.Unlock()
		e.Requests = append(e.Requests, string(b))
		if strings.HasSuffix(r.URL.Path, ":annotate") {
			e.Annotated = append(e.Annotated, string(b))
			_, _ = w.Write([]byte("{}"))
			return
		}
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	c, err := revokegpt.New(Secret, srv.URL+"/v1/siteverify")
	if err != nil {
		t.Fatal(err)
	}
	return e, c
}

// Fraud is the fraudPreventionAssessment member of an answer with every risk at risk.
func Fraud(risk float64, unscored bool) string {
	u := ""
	if unscored {
		u = `,"unscored":true`
	}
	return fmt.Sprintf(`,"fraudPreventionAssessment":{"transactionRisk":%[1]v,"cardTestingRisk":%[1]v,"stolenInstrumentRisk":%[1]v,"riskReasons":[],"cardTestingVerdict":{"risk":%[1]v},"stolenInstrumentVerdict":{"risk":%[1]v}%[2]s}`, risk, u)
}

// Phone is the phoneFraudAssessment member of an answer.
func Phone(risk float64, unscored bool) string {
	u := ""
	if unscored {
		u = `,"unscored":true`
	}
	return fmt.Sprintf(`,"phoneFraudAssessment":{"smsTollFraudVerdict":{"risk":%v,"reasons":[]%s}}`, risk, u)
}
