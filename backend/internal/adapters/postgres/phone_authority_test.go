package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestAuthorityPhoneLocksShareWeChatNamespaceAndGlobalOrder(t *testing.T) {
	userID := identity.UserID("user_sms_target")
	keys := sortedAuthorityLockKeys(
		authorityUserLockKey(userID),
		authorityPhoneLockKey("+8613800000099"),
		authorityPhoneLockKey("+8613800000088"),
		authorityPhoneLockKey("+8613800000099"),
		authorityWeChatLockKey("wx-app", "openid-target"),
		authorityPhoneLockKey(""),
	)
	want := []string{
		"phone:+8613800000088",
		"phone:+8613800000099",
		"user:user_sms_target",
		"wechat:wx-app:openid-target",
	}
	if strings.Join(keys, "|") != strings.Join(want, "|") {
		t.Fatalf("authority keys=%q want=%q", keys, want)
	}
}

func TestPhoneVerifySQLPinsOwnerCheckAndSecurityRevision(t *testing.T) {
	owner := strings.ToLower(phoneVerifyLockOtherOwnerSQL)
	for _, fragment := range []string{"where phone = $1", "id <> $2", "for update"} {
		if !strings.Contains(owner, fragment) {
			t.Fatalf("owner query missing %q: %s", fragment, owner)
		}
	}
	advance := strings.ToLower(phoneVerifyAdvanceUserSQL)
	for _, fragment := range []string{
		"phone = $2", "phone_verified = true", "status = 'active'",
		"version = version + 1", "security_epoch = security_epoch + 1",
		"version = $3", "security_epoch = $4",
	} {
		if !strings.Contains(advance, fragment) {
			t.Fatalf("advance query missing %q: %s", fragment, advance)
		}
	}
}

func TestSMSPhoneAuthorityEffectAppendsAuditAndOutboxWithoutPhonePII(t *testing.T) {
	digest, err := DeriveWeChatAuthorityReplayDigest(WeChatAuthorityReplayMaterial{
		Flow:             WeChatAuthorityFlowSMSPhoneVerified,
		TargetUserID:     "user_sms_effect",
		AuthorityVersion: 4,
		SecurityEpoch:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx := newWeChatAuthorityFakeTx()
	receipt, err := NewWeChatAuthorityEffectStore().RecordTx(context.Background(), tx, WeChatAuthorityEffect{
		ReplayDigest: digest,
		Kind:         WeChatAuthorityEffectSMSPhoneVerified,
		TargetUserID: "user_sms_effect",
		OccurredAt:   time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.events) != 2 || tx.events[receipt.AuditEventID].EventType != "account.phone_verified" ||
		tx.events[receipt.PendingEventID].EventType != wechatNotificationPendingEvent {
		t.Fatalf("receipt=%+v events=%+v", receipt, tx.events)
	}
	for _, forbidden := range []string{"+8613800000099", "13800000099"} {
		if strings.Contains(strings.Join(tx.persistedRepresentations, "\n"), forbidden) {
			t.Fatalf("SMS phone effect persisted phone PII %q", forbidden)
		}
	}
}

func TestSMSPhoneNotificationTemplateIsFixedAndProviderNeutral(t *testing.T) {
	subject, body, ok := weChatNotificationTemplate(WeChatAuthorityEffectSMSPhoneVerified)
	if !ok || subject != "United Pass 安全提醒：手机号已更新" || !strings.Contains(body, "通过短信验证更新手机号") {
		t.Fatalf("SMS phone notification subject=%q body=%q ok=%v", subject, body, ok)
	}
}
