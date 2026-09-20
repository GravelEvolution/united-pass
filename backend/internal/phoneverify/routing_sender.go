package phoneverify

import (
	"context"
	"errors"
	"strings"
)

const mainlandChinaPrefix = "+86"

type routingSender struct {
	domestic      Sender
	international Sender
}

func NewRoutingSender(domestic, international Sender) Sender {
	if domestic == nil && international == nil {
		return nil
	}
	if domestic == nil {
		return international
	}
	if international == nil {
		return domestic
	}
	return &routingSender{domestic: domestic, international: international}
}

func (s *routingSender) SendCode(ctx context.Context, phone, code string) error {
	if strings.HasPrefix(phone, mainlandChinaPrefix) {
		if s.domestic == nil {
			return errors.New("phoneverify: domestic SMS sender is not configured")
		}
		return s.domestic.SendCode(ctx, phone, code)
	}
	return s.international.SendCode(ctx, phone, code)
}
