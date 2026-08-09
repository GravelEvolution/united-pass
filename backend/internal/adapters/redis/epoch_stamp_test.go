//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the F2 legacy decode normalization rules (ADR-0007)
//

package redis

import (
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// TestNormalizeStamp covers the single executable legacy decode rule for
// session records (ADR-0007 F2): an absent stamp decodes to generation 1,
// stamped records pass through untouched.
func TestNormalizeStamp(t *testing.T) {
	cases := []struct {
		name  string
		epoch securitystate.Epoch
		want  securitystate.Epoch
	}{
		{"legacy absent stamp normalizes to generation 1", 0, 1},
		{"generation 1 stays generation 1", 1, 1},
		{"current generations pass through", 7, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := session.SessionRecord{SecurityEpoch: tc.epoch}
			normalizeStamp(&record)
			if record.SecurityEpoch != tc.want {
				t.Fatalf("epoch = %d, want %d", record.SecurityEpoch, tc.want)
			}
		})
	}
}

// TestDecodePayloadLegacyRecord proves a pre-ADR-0007 Redis payload (JSON
// without the securityEpoch field) decodes executable as generation 1.
func TestDecodePayloadLegacyRecord(t *testing.T) {
	legacy := `{"version":1,"sessionId":"up-session-legacy","userId":"user_legacy","provider":"zitadel"}`
	record, ok := decodePayload(legacy)
	if !ok {
		t.Fatal("legacy payload must decode")
	}
	if record.SecurityEpoch != 1 {
		t.Fatalf("legacy epoch = %d, want normalized generation 1", record.SecurityEpoch)
	}

	stamped := `{"version":1,"sessionId":"up-session-new","userId":"user_new","provider":"zitadel","securityEpoch":4}`
	record, ok = decodePayload(stamped)
	if !ok {
		t.Fatal("stamped payload must decode")
	}
	if record.SecurityEpoch != 4 {
		t.Fatalf("stamped epoch = %d, want 4", record.SecurityEpoch)
	}

	if _, ok := decodePayload(nil); ok {
		t.Fatal("missing payload must report not ok")
	}
	if _, ok := decodePayload("{corrupt"); ok {
		t.Fatal("corrupt payload must report not ok")
	}
}

// TestRequireStamped covers the write-side fail-closed rule: post-migration
// writes must always carry a stamp.
func TestRequireStamped(t *testing.T) {
	if err := requireStamped(session.SessionRecord{}); err == nil {
		t.Fatal("an unstamped write must fail closed")
	}
	if err := requireStamped(session.SessionRecord{SecurityEpoch: 1}); err != nil {
		t.Fatalf("a stamped write err = %v, want nil", err)
	}
}

// TestNormalizeReauthEpochs covers the same F2 rule for challenges and
// grants: absent stamps decode as generation 1, stamped data untouched.
func TestNormalizeReauthEpochs(t *testing.T) {
	challenge := &auth.ReauthChallengeData{}
	normalizeReauthChallengeEpoch(challenge)
	if challenge.SecurityEpoch != 1 {
		t.Fatalf("legacy challenge epoch = %d, want 1", challenge.SecurityEpoch)
	}

	stampedChallenge := &auth.ReauthChallengeData{SecurityEpoch: 3}
	normalizeReauthChallengeEpoch(stampedChallenge)
	if stampedChallenge.SecurityEpoch != 3 {
		t.Fatalf("stamped challenge epoch = %d, want 3", stampedChallenge.SecurityEpoch)
	}

	grant := &auth.ReauthGrantData{}
	normalizeReauthGrantEpoch(grant)
	if grant.SecurityEpoch != 1 {
		t.Fatalf("legacy grant epoch = %d, want 1", grant.SecurityEpoch)
	}

	stampedGrant := &auth.ReauthGrantData{SecurityEpoch: 5}
	normalizeReauthGrantEpoch(stampedGrant)
	if stampedGrant.SecurityEpoch != 5 {
		t.Fatalf("stamped grant epoch = %d, want 5", stampedGrant.SecurityEpoch)
	}
}
