package postgres

import (
	"strings"
	"testing"
)

func TestAdminStepUpActiveReadIsBoundToSessionUserAndFreshness(t *testing.T) {
	for _, fragment := range []string{"session_id=$1", "user_id=$2", "verified_at<=$3", "expires_at>$3", "revoked_at IS NULL"} {
		if !strings.Contains(adminStepUpActiveReadSQL, fragment) {
			t.Fatalf("active step-up query missing %q: %s", fragment, adminStepUpActiveReadSQL)
		}
	}
}
