package wechat

import "testing"

func TestValidateCodeRejectsUnsafeValues(t *testing.T) {
	for _, value := range []string{"", " code", "code ", "code\nnext"} {
		if err := ValidateCode(value); err != ErrInvalidCode {
			t.Fatalf("ValidateCode(%q) error = %v, want ErrInvalidCode", value, err)
		}
	}
	if err := ValidateCode("one-time-code"); err != nil {
		t.Fatalf("ValidateCode valid value: %v", err)
	}
}

func TestSubjectUsesAppScopedOpenIDAcrossUnionIDAppearance(t *testing.T) {
	withoutUnion, err := Subject("", "open-456")
	if err != nil || withoutUnion != "open-456" {
		t.Fatalf("Subject without union = %q, %v", withoutUnion, err)
	}
	withUnion, err := Subject("union-123", "open-456")
	if err != nil || withUnion != withoutUnion {
		t.Fatalf("UnionID appearance changed subject: before=%q after=%q err=%v", withoutUnion, withUnion, err)
	}
	if _, err := Subject("", ""); err != ErrRejected {
		t.Fatalf("Subject blank error = %v, want ErrRejected", err)
	}
}
