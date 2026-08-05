package observability

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want ErrorClass
	}{
		{name: "nil", err: nil, want: ErrorClassInternal},
		{name: "context cancelled", err: context.Canceled, want: ErrorClassContext},
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: ErrorClassContext},
		{name: "network timeout", err: &net.DNSError{IsTimeout: true}, want: ErrorClassTimeout},
		{
			name: "connection refused",
			err:  &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")},
			want: ErrorClassNetwork,
		},
		{name: "generic", err: errors.New("something broke"), want: ErrorClassInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyError(tc.err); got != tc.want {
				t.Errorf("ClassifyError = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRedactedErrorStripsSensitiveContent(t *testing.T) {
	raw := "redis: dial tcp: 38.246.253.223:6379 connection refused; url=redis://:secret@38.246.253.223:6379/0"
	got := RedactedError(errors.New(raw), 0)

	for _, forbidden := range []string{"38.246.253.223", "6379", "secret@"} {
		if contains(got, forbidden) {
			t.Errorf("RedactedError output %q still contains %q", got, forbidden)
		}
	}
	if !contains(got, "[redacted]") {
		t.Errorf("RedactedError output %q should contain redaction markers", got)
	}
}

func TestRedactedErrorTruncates(t *testing.T) {
	got := RedactedError(errors.New("a very long error message that should be cut short"), 20)
	if len(got) > 30 {
		t.Errorf("RedactedError output length = %d, want truncated", len(got))
	}
}

func TestRedactedErrorNil(t *testing.T) {
	if got := RedactedError(nil, 100); got != "" {
		t.Errorf("RedactedError(nil) = %q, want empty", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}
