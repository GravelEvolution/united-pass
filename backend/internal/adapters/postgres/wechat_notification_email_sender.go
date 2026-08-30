package postgres

import (
	"context"
	"net/mail"
	"strings"

	mailservice "github.com/GravelEvolution/united-pass/backend/internal/email"
)

const weChatNotificationMessageDomain = "auth.moonstone.org.cn"

// WeChatNotificationEmailSender turns the PII-free outbox intent into a fixed
// security message. The destination exists only for this call and is never
// returned in an error. SMTP delivery is at-least-once; the deterministic
// Message-ID and idempotency header let a capable relay suppress duplicates.
type WeChatNotificationEmailSender struct {
	sender mailservice.Sender
}

func NewWeChatNotificationEmailSender(sender mailservice.Sender) *WeChatNotificationEmailSender {
	return &WeChatNotificationEmailSender{sender: sender}
}

func (s *WeChatNotificationEmailSender) Send(ctx context.Context, delivery WeChatNotificationDelivery) error {
	if s == nil || s.sender == nil || !validWeChatNotificationDelivery(delivery) {
		return ErrWeChatAuthorityEffectInvalid
	}
	address, err := mail.ParseAddress(delivery.Destination)
	if err != nil || address.Address != delivery.Destination {
		return weChatNotificationPermanentFailure{class: "provider_rejected"}
	}
	subject, body, ok := weChatNotificationTemplate(delivery.Kind)
	if !ok {
		return ErrWeChatAuthorityEffectInvalid
	}
	messageID := "<" + delivery.NotificationID + "@" + weChatNotificationMessageDomain + ">"
	if err := s.sender.Send(ctx, mailservice.Message{
		To: delivery.Destination, Subject: subject, HTML: body,
		MessageID: messageID, IdempotencyKey: delivery.NotificationID,
	}); err != nil {
		// Never expose the SMTP error: providers commonly echo recipients,
		// credentials or server diagnostics. The outbox retains the intent.
		return ErrWeChatNotificationTransient
	}
	return nil
}

func validWeChatNotificationDelivery(delivery WeChatNotificationDelivery) bool {
	return delivery.NotificationID != "" && strings.HasPrefix(delivery.NotificationID, "wxn_") &&
		len(delivery.NotificationID) == len("wxn_")+32 && delivery.TargetUserID != "" &&
		delivery.Destination != "" && !strings.ContainsAny(delivery.NotificationID, "\r\n <>@")
}

func weChatNotificationTemplate(kind WeChatAuthorityEffectKind) (string, string, bool) {
	const footer = `<p>如果这不是你本人进行的操作，请立即登录 United Pass 检查账户安全设置并联系支持团队。</p><p>MoonStone United Pass</p>`
	switch kind {
	case WeChatAuthorityEffectExistingLink:
		return "United Pass 安全提醒：微信已绑定", `<p>你的 United Pass 账户已成功绑定微信小程序快捷登录。</p>` + footer, true
	case WeChatAuthorityEffectExistingPhone:
		return "United Pass 安全提醒：微信手机号已验证", `<p>你的 United Pass 账户已通过微信小程序完成手机号验证。</p>` + footer, true
	case WeChatAuthorityEffectExistingLinkPhone:
		return "United Pass 安全提醒：微信快捷登录已启用", `<p>你的 United Pass 账户已绑定微信小程序快捷登录，并完成手机号验证。</p>` + footer, true
	case WeChatAuthorityEffectPendingReserved:
		return "欢迎使用 United Pass 微信快捷登录", `<p>你的 United Pass 账户已完成微信小程序注册与绑定。</p>` + footer, true
	case WeChatAuthorityEffectPendingPhoneVerified:
		return "United Pass 安全提醒：微信手机号已验证", `<p>你的 United Pass 账户已通过微信小程序补充并验证手机号。</p>` + footer, true
	default:
		return "", "", false
	}
}

type weChatNotificationPermanentFailure struct{ class string }

func (e weChatNotificationPermanentFailure) Error() string            { return "notification delivery rejected" }
func (e weChatNotificationPermanentFailure) Permanent() bool          { return true }
func (e weChatNotificationPermanentFailure) SafeFailureClass() string { return e.class }

var (
	_ WeChatNotificationSender      = (*WeChatNotificationEmailSender)(nil)
	_ WeChatNotificationSendFailure = weChatNotificationPermanentFailure{}
)
