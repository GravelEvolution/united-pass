package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunRejectsMissingAuditInputsBeforeLoadingConfiguration(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--actor-user-id", "user_0123456789abcdef0123456789abcdef"},
		{"--request-id", "req_policy_reconcile"},
		{"unexpected"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Fatalf("run(%v) code = %d, want 2", args, code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("run(%v) wrote stdout %q", args, stdout.String())
		}
		if len(args) == 1 && args[0] == "unexpected" {
			continue
		}
		if !strings.Contains(stderr.String(), "error=invalid_arguments") {
			t.Fatalf("run(%v) stderr = %q", args, stderr.String())
		}
	}
}
