package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	mailservice "github.com/GravelEvolution/united-pass/backend/internal/email"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestWeChatNotificationEmailSenderUsesDeterministicHeadersAndFixedBody(t *testing.T) {
	fake := &capturingMailSender{}
	sender := NewWeChatNotificationEmailSender(fake)
	delivery := WeChatNotificationDelivery{
		NotificationID: "wxn_0123456789abcdef0123456789abcdef",
		Kind:           WeChatAuthorityEffectExistingLinkPhone, TargetUserID: identity.UserID("usr_1"),
		Destination: "owner@example.com",
	}
	if err := sender.Send(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	if fake.message.MessageID != "<"+delivery.NotificationID+"@auth.moonstone.org.cn>" || fake.message.IdempotencyKey != delivery.NotificationID {
		t.Fatalf("unexpected deterministic identifiers: %#v", fake.message)
	}
	if strings.Contains(fake.message.HTML, string(delivery.TargetUserID)) || strings.Contains(fake.message.HTML, delivery.Destination) {
		t.Fatal("security template must not embed account identifiers")
	}
}

func TestWeChatNotificationEmailSenderUsesFixedPendingPhoneVerifiedTemplate(t *testing.T) {
	fake := &capturingMailSender{}
	delivery := WeChatNotificationDelivery{
		NotificationID: "wxn_0123456789abcdef0123456789abcdef",
		Kind:           WeChatAuthorityEffectPendingPhoneVerified,
		TargetUserID:   identity.UserID("usr_pending_phone"),
		Destination:    "owner@example.com",
	}
	if err := NewWeChatNotificationEmailSender(fake).Send(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	const wantHTML = `<p>你的 United Pass 账户已通过微信小程序补充并验证手机号。</p><p>如果这不是你本人进行的操作，请立即登录 United Pass 检查账户安全设置并联系支持团队。</p><p>MoonStone United Pass</p>`
	if fake.message.Subject != "United Pass 安全提醒：微信手机号已验证" || fake.message.HTML != wantHTML {
		t.Fatalf("pending-phone template=%#v", fake.message)
	}
	if strings.Contains(fake.message.HTML, delivery.Destination) || strings.Contains(fake.message.HTML, string(delivery.TargetUserID)) {
		t.Fatal("pending-phone template must not embed account identifiers")
	}
}

func TestWeChatNotificationEmailSenderRedactsTransportError(t *testing.T) {
	fake := &capturingMailSender{err: errors.New("smtp rejected owner@example.com with secret token")}
	sender := NewWeChatNotificationEmailSender(fake)
	err := sender.Send(context.Background(), WeChatNotificationDelivery{
		NotificationID: "wxn_0123456789abcdef0123456789abcdef",
		Kind:           WeChatAuthorityEffectExistingLink, TargetUserID: identity.UserID("usr_1"),
		Destination: "owner@example.com",
	})
	if !errors.Is(err, ErrWeChatNotificationTransient) || strings.Contains(err.Error(), "owner@example.com") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("transport error was not safely classified: %v", err)
	}
}

func TestWeChatNotificationEmailSenderRejectsInvalidDestinationPermanently(t *testing.T) {
	err := NewWeChatNotificationEmailSender(&capturingMailSender{}).Send(context.Background(), WeChatNotificationDelivery{
		NotificationID: "wxn_0123456789abcdef0123456789abcdef",
		Kind:           WeChatAuthorityEffectExistingLink, TargetUserID: identity.UserID("usr_1"), Destination: "bad\r\nBcc:x@y.test",
	})
	var classified WeChatNotificationSendFailure
	if !errors.As(err, &classified) || !classified.Permanent() || classified.SafeFailureClass() != "provider_rejected" {
		t.Fatalf("invalid address error = %v", err)
	}
}

type capturingMailSender struct {
	message mailservice.Message
	err     error
}

func (s *capturingMailSender) Send(_ context.Context, message mailservice.Message) error {
	s.message = message
	return s.err
}
