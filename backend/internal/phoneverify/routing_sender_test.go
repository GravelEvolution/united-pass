package phoneverify

import (
	"context"
	"errors"
	"testing"
)

type recordingSender struct {
	calls []string
	err   error
}

func (s *recordingSender) SendCode(_ context.Context, phone, _ string) error {
	s.calls = append(s.calls, phone)
	return s.err
}

func TestRoutingSenderSplitsDomesticAndInternationalNumbers(t *testing.T) {
	domestic := &recordingSender{}
	international := &recordingSender{}
	sender := NewRoutingSender(domestic, international)

	if err := sender.SendCode(context.Background(), "+8613800138000", "123456"); err != nil {
		t.Fatal(err)
	}
	if err := sender.SendCode(context.Background(), "+37257013843", "123456"); err != nil {
		t.Fatal(err)
	}
	if len(domestic.calls) != 1 || domestic.calls[0] != "+8613800138000" {
		t.Fatalf("domestic calls=%v", domestic.calls)
	}
	if len(international.calls) != 1 || international.calls[0] != "+37257013843" {
		t.Fatalf("international calls=%v", international.calls)
	}
}

func TestRoutingSenderFallsBackToDomesticWhenInternationalIsAbsent(t *testing.T) {
	domestic := &recordingSender{}
	sender := NewRoutingSender(domestic, nil)

	if err := sender.SendCode(context.Background(), "+37257013843", "123456"); err != nil {
		t.Fatal(err)
	}
	if len(domestic.calls) != 1 || domestic.calls[0] != "+37257013843" {
		t.Fatalf("domestic calls=%v", domestic.calls)
	}
	if NewRoutingSender(nil, nil) != nil {
		t.Fatal("expected nil sender when both routes are absent")
	}
}

func TestRoutingSenderPropagatesProviderFailure(t *testing.T) {
	providerErr := errors.New("provider rejected the request")
	sender := NewRoutingSender(&recordingSender{}, &recordingSender{err: providerErr})

	if err := sender.SendCode(context.Background(), "+37257013843", "123456"); !errors.Is(err, providerErr) {
		t.Fatalf("error=%v", err)
	}
}
