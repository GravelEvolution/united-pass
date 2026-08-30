package email

import (
	"strings"
	"testing"
)

func TestNewSMTPRequiresHost(t *testing.T) {
	if _, err := NewSMTP(Config{}); err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestNewSMTPRequiresFrom(t *testing.T) {
	if _, err := NewSMTP(Config{Host: "smtp.example.com"}); err == nil {
		t.Fatal("expected error for empty from address")
	}
}

func TestValidateMessage(t *testing.T) {
	ok := Message{To: "a@b.com", Subject: "hi", HTML: "<p>hi</p>"}
	if err := validateMessage(ok); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cases := []Message{
		{To: "", Subject: "hi", HTML: "<p>hi</p>"},
		{To: "a@b.com", Subject: "", HTML: "<p>hi</p>"},
		{To: "a@b.com", Subject: "hi", HTML: ""},
		{To: strings.Repeat("x", 300), Subject: "hi", HTML: "<p>hi</p>"},
	}
	for i, c := range cases {
		if err := validateMessage(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestRenderMessageHeaders(t *testing.T) {
	body, err := renderMessage("support@example.com", "MoonStone", Message{
		To: "a@b.com", Subject: "你好", HTML: "<p>hi</p>",
		MessageID:      "<wxn_0123456789abcdef0123456789abcdef@auth.moonstone.org.cn>",
		IdempotencyKey: "wxn_0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.HasPrefix(text, "From: ") {
		t.Fatalf("body must start with From header: %q", text[:20])
	}
	for _, want := range []string{"To: a@b.com", "Content-Type: text/html; charset=UTF-8", "Subject: =?UTF-8?", "Message-ID: <wxn_", "X-UnitedPass-Idempotency-Key: wxn_"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
}

func TestValidateMessageRejectsInjectedDeterministicHeaders(t *testing.T) {
	base := Message{To: "a@b.com", Subject: "hi", HTML: "<p>hi</p>"}
	cases := []Message{
		{To: base.To, Subject: base.Subject, HTML: base.HTML, MessageID: "<safe@example.com>\r\nBcc: attacker@example.com"},
		{To: base.To, Subject: base.Subject, HTML: base.HTML, IdempotencyKey: "safe\r\nBcc:attacker"},
		{To: "MoonStone <a@b.com>", Subject: base.Subject, HTML: base.HTML},
	}
	for i, candidate := range cases {
		if err := validateMessage(candidate); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}
