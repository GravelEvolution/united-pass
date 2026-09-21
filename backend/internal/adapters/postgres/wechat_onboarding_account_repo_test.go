package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatonboarding"
)

var _ wechatonboarding.AccountRepository = (*WeChatOnboardingAccountRepository)(nil)
var _ wechat.PhoneWriter = (*WeChatOnboardingAccountRepository)(nil)

func TestEvaluateWeChatOnboardingLinksFailsClosedOnEveryCompetingBinding(t *testing.T) {
	tests := []struct {
		name   string
		links  []wechatOnboardingLink
		linked bool
		err    error
	}{
		{name: "unbound"},
		{name: "exact idempotent", links: []wechatOnboardingLink{{userID: "user_target", subject: "wx_subject"}}, linked: true},
		{name: "subject belongs to another account", links: []wechatOnboardingLink{{userID: "user_other", subject: "wx_subject"}}, err: wechatonboarding.ErrIdentityConflict},
		{name: "target already has another subject", links: []wechatOnboardingLink{{userID: "user_target", subject: "wx_other"}}, err: wechatonboarding.ErrIdentityConflict},
		{name: "duplicate exact rows fail closed", links: []wechatOnboardingLink{{userID: "user_target", subject: "wx_subject"}, {userID: "user_target", subject: "wx_subject"}}, err: wechatonboarding.ErrIdentityConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			linked, err := evaluateWeChatOnboardingLinks(test.links, "user_target", "wx_subject")
			if linked != test.linked || !errors.Is(err, test.err) {
				t.Fatalf("linked=%v err=%v, want linked=%v err=%v", linked, err, test.linked, test.err)
			}
		})
	}
}

func TestDecideWeChatOnboardingPhoneNeverOverwritesExistingContact(t *testing.T) {
	tests := []struct {
		name         string
		existing     string
		verified     bool
		proof        string
		add          bool
		wantConflict bool
	}{
		{name: "no proof writes nothing", existing: "+8613800000001", verified: true},
		{name: "empty target accepts proof", proof: "+8613800000001", add: true},
		{name: "same verified phone is idempotent", existing: "+8613800000001", verified: true, proof: "+8613800000001"},
		{name: "different verified phone is preserved", existing: "+8613800000001", verified: true, proof: "+8613800000002", wantConflict: true},
		{name: "same legacy unverified phone is upgraded", existing: "+8613800000001", proof: "+8613800000001", add: true},
		{name: "inconsistent empty verified state fails closed", verified: true, proof: "+8613800000001", wantConflict: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			add, err := decideWeChatOnboardingPhone(test.existing, test.verified, test.proof)
			if add != test.add || errors.Is(err, wechatonboarding.ErrPhoneConflict) != test.wantConflict {
				t.Fatalf("add=%v err=%v, want add=%v conflict=%v", add, err, test.add, test.wantConflict)
			}
		})
	}
}

func TestWeChatOnboardingAuthoritySQLHasNarrowMutationAllowlist(t *testing.T) {
	lookup := strings.ToLower(strings.Join(strings.Fields(wechatOnboardingFindEmailSQL), " "))
	for _, required := range []string{"lower(btrim(email)) = $1", "order by id", "limit 2"} {
		if !strings.Contains(lookup, required) {
			t.Fatalf("normalized-email lookup missing %q: %s", required, lookup)
		}
	}
	for _, required := range []string{"lower(btrim(email))", "security_epoch"} {
		if !strings.Contains(lookup, required) {
			t.Fatalf("authority snapshot lookup missing %q: %s", required, lookup)
		}
	}

	lockedUser := strings.ToLower(strings.Join(strings.Fields(wechatOnboardingLockUserSQL), " "))
	for _, required := range []string{"status", "lower(btrim(email))", "version", "security_epoch", "for update"} {
		if !strings.Contains(lockedUser, required) {
			t.Fatalf("authority snapshot lock missing %q: %s", required, lockedUser)
		}
	}

	links := strings.ToLower(strings.Join(strings.Fields(wechatOnboardingLockLinksSQL), " "))
	for _, required := range []string{"provider_tenant_id = $2", "provider_subject = $3 or user_id = $4", "for update"} {
		if !strings.Contains(links, required) {
			t.Fatalf("identity-link lock missing %q: %s", required, links)
		}
	}

	update := strings.ToLower(strings.Join(strings.Fields(wechatOnboardingAdvanceUserSQL), " "))
	setStart, whereStart := strings.Index(update, "set "), strings.Index(update, " where ")
	if setStart < 0 || whereStart <= setStart {
		t.Fatalf("unexpected account update SQL: %s", update)
	}
	setClause := update[setStart:whereStart]
	for _, forbidden := range []string{"display_name", "nickname", "avatar_url", "email", "status", "persona", "role", "permission"} {
		if strings.Contains(setClause, forbidden) {
			t.Fatalf("account update mutates forbidden field %q: %s", forbidden, setClause)
		}
	}
	for _, required := range []string{"phone =", "phone_verified =", "updated_at =", "version = version + 1", "security_epoch = security_epoch + 1"} {
		if !strings.Contains(setClause, required) {
			t.Fatalf("account update missing allowed mutation %q: %s", required, setClause)
		}
	}
}

func TestValidateWeChatOnboardingAccountSnapshotFailsClosedOnConcurrentAuthorityChanges(t *testing.T) {
	input := wechatonboarding.BindExistingInput{
		UserID: "user_target", TenantID: "wx-app", Subject: "openid",
		NormalizedEmail: "owner@example.com", ExpectedVersion: 7, ExpectedSecurityEpoch: 4,
	}
	tests := []struct {
		name            string
		status          string
		normalizedEmail string
		version         int
		epoch           int64
		want            error
	}{
		{name: "unchanged", status: "active", normalizedEmail: "owner@example.com", version: 7, epoch: 4},
		{name: "status changed", status: "disabled", normalizedEmail: "owner@example.com", version: 7, epoch: 4, want: wechatonboarding.ErrAccountInactive},
		{name: "email changed", status: "active", normalizedEmail: "other@example.com", version: 7, epoch: 4, want: wechatonboarding.ErrAccountChanged},
		{name: "version changed", status: "active", normalizedEmail: "owner@example.com", version: 8, epoch: 4, want: wechatonboarding.ErrAccountChanged},
		{name: "security epoch changed", status: "active", normalizedEmail: "owner@example.com", version: 7, epoch: 5, want: wechatonboarding.ErrAccountChanged},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateWeChatOnboardingAccountSnapshot(test.status, test.normalizedEmail, test.version, securitystate.Epoch(test.epoch), input)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestWeChatOnboardingSerializableFailureClassification(t *testing.T) {
	for _, code := range []string{"40001", "40P01"} {
		if !isWeChatOnboardingSerializationFailure(&pgconn.PgError{Code: code}) {
			t.Fatalf("SQLSTATE %s was not classified as retryable", code)
		}
	}
	if isWeChatOnboardingSerializationFailure(&pgconn.PgError{Code: "23505"}) || isWeChatOnboardingSerializationFailure(errors.New("unavailable")) {
		t.Fatal("non-serialization error was classified as retryable")
	}
}
