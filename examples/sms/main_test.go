package main

import (
	"context"
	"strings"
	"testing"

	"github.com/ZaeemSattar/revokegpt-go/examples/internal/edgetest"
)

type fakeSMS struct{ sent []string }

func (f *fakeSMS) Send(_ context.Context, to, body string) error {
	f.sent = append(f.sent, to+"|"+body)
	return nil
}

func TestSendOnlyBelowTheThreshold(t *testing.T) {
	for _, tc := range []struct {
		extra string
		want  string
	}{
		{edgetest.Phone(0.1, false), "sent"}, {edgetest.Phone(0.39, false), "sent"}, {edgetest.Phone(0.4, false), "withheld"}, {edgetest.Phone(0.5, true), "withheld"}, {edgetest.Phone(0.1, true), "withheld"}, {"", "withheld"},
	} {
		e, rg := edgetest.New(t, tc.extra)
		s := &fakeSMS{}
		got, err := SendCodeIfSafe(context.Background(), rg, s, "tok_abc", "+447700900123", "123456")
		if err != nil || got != tc.want || (tc.want == "sent") != (len(s.sent) == 1) {
			t.Fatalf("%s: %q %v %v", tc.extra, got, err, s.sent)
		}
		if !strings.Contains(e.Requests[0], `"userIds":[{"phoneNumber":"+447700900123"}]`) {
			t.Fatal(e.Requests[0])
		}
	}
}
