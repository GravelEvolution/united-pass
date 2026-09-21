package adminbootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type localStub struct{ value LocalIdentity }

func (s localStub) ReadExact(context.Context, identity.UserID, string, string, string) (LocalIdentity, error) {
	return s.value, nil
}

type providerStub struct{ value ProviderIdentity }

func (s providerStub) ReadExact(context.Context, string, string) (ProviderIdentity, error) {
	return s.value, nil
}

type hashStub struct{}

func (hashStub) Hash(context.Context, string) (string, string, error) {
	return "$argon2id$fixture", "pepper-1", nil
}

type cipherStub struct{}

func (cipherStub) Encrypt(adminstepup.EncryptionPurpose, string, string, int64, string) (adminstepup.EncryptedValue, error) {
	return adminstepup.EncryptedValue{KeyID: "enc-1", Nonce: []byte{1}, Ciphertext: []byte{2}}, nil
}

type repositoryStub struct {
	applied *Mutation
	state   BootstrapState
	err     error
}

func (r *repositoryStub) Apply(_ context.Context, m Mutation) (BootstrapState, error) {
	r.applied = &m
	if r.err != nil {
		return BootstrapState{}, r.err
	}
	r.state = m.State
	return r.state, nil
}
func (r *repositoryStub) Readback(context.Context, identity.UserID, string) (BootstrapState, error) {
	return r.state, r.err
}

func TestBootstrapRequiresTwoDistinctApprovalsAndCreatesMustRotateState(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 2, 3, 0, time.UTC)
	change := testChange(now)
	keys, private := testApprovalKeys(t)
	repo := &repositoryStub{}
	service, err := NewService(Dependencies{Local: localStub{LocalIdentity{UserID: change.TargetUserID, Status: identity.UserStatusActive, Provider: "zitadel", ProviderTenantID: "tenant_exact", ProviderSubject: "subject_exact"}}, Provider: providerStub{ProviderIdentity{Subject: "subject_exact", LoginName: ExpectedLoginName, Enabled: true}}, Repository: repo, Hasher: hashStub{}, Cipher: cipherStub{}, Approvals: keys, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	approvals := []Approval{signTestApproval(t, change, "operator_a", "key_a", private[0], now), signTestApproval(t, change, "operator_b", "key_b", private[1], now)}
	result, err := service.Bootstrap(context.Background(), Input{Change: change, Approvals: approvals, Question: "安全问题足够长吗？", Answer: "安全答案足够长"})
	if err != nil || result.Username != ExpectedLoginName || !result.MustRotate || result.EventID != ShanghaiEventID {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if repo.applied == nil || len(repo.applied.Approvals) != 2 || repo.applied.State.Binding.Role != adminroles.RoleSuperAdmin || !repo.applied.Credential.Challenge.MustRotate {
		t.Fatalf("mutation=%+v", repo.applied)
	}
	if result.Status == "" || result.BindingID == "" {
		t.Fatal(result)
	}
}

func TestBootstrapRejectsSameOperatorMismatchedIdentityAndReplay(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 2, 3, 0, time.UTC)
	change := testChange(now)
	keys, private := testApprovalKeys(t)
	approvals := []Approval{signTestApproval(t, change, "operator_a", "key_a", private[0], now), signTestApproval(t, change, "operator_a", "key_a", private[0], now)}
	repo := &repositoryStub{}
	service, _ := NewService(Dependencies{Local: localStub{LocalIdentity{UserID: change.TargetUserID, Status: identity.UserStatusActive, Provider: "zitadel", ProviderTenantID: "tenant_exact", ProviderSubject: "subject_exact"}}, Provider: providerStub{ProviderIdentity{Subject: "subject_exact", LoginName: ExpectedLoginName, Enabled: true}}, Repository: repo, Hasher: hashStub{}, Cipher: cipherStub{}, Approvals: keys, Now: func() time.Time { return now }})
	if _, err := service.Bootstrap(context.Background(), Input{Change: change, Approvals: approvals, Question: "安全问题足够长吗？", Answer: "安全答案足够长"}); !errors.Is(err, ErrInvalidApproval) {
		t.Fatalf("same operator err=%v", err)
	}
	service.deps.Provider = providerStub{ProviderIdentity{Subject: "subject_exact", LoginName: "wrong", Enabled: true}}
	if _, err := service.Readback(context.Background(), change); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("identity err=%v", err)
	}
	repo.err = ErrApprovalReplay
	service.deps.Provider = providerStub{ProviderIdentity{Subject: "subject_exact", LoginName: ExpectedLoginName, Enabled: true}}
	approvals = []Approval{signTestApproval(t, change, "operator_a", "key_a", private[0], now), signTestApproval(t, change, "operator_b", "key_b", private[1], now)}
	if _, err := service.Bootstrap(context.Background(), Input{Change: change, Approvals: approvals, Question: "安全问题足够长吗？", Answer: "安全答案足够长"}); !errors.Is(err, ErrApprovalReplay) {
		t.Fatalf("replay err=%v", err)
	}
}

func TestReadbackFailsClosedOnDrift(t *testing.T) {
	now := time.Now().UTC()
	change := testChange(now)
	keys, _ := testApprovalKeys(t)
	repo := &repositoryStub{state: BootstrapState{Binding: adminroles.Binding{UserID: change.TargetUserID, Role: adminroles.RoleAdmin}}}
	service, _ := NewService(Dependencies{Local: localStub{LocalIdentity{UserID: change.TargetUserID, Status: identity.UserStatusActive, Provider: "zitadel", ProviderTenantID: "tenant_exact", ProviderSubject: "subject_exact"}}, Provider: providerStub{ProviderIdentity{Subject: "subject_exact", LoginName: ExpectedLoginName, Enabled: true}}, Repository: repo, Hasher: hashStub{}, Cipher: cipherStub{}, Approvals: keys})
	if _, err := service.Readback(context.Background(), change); !errors.Is(err, ErrBootstrapDrift) {
		t.Fatalf("drift err=%v", err)
	}
}

func testChange(now time.Time) Change {
	return Change{Action: GrantSuper, TargetUserID: "user_el107t", ExpectedUsername: ExpectedLoginName, Provider: "zitadel", ProviderTenantID: "tenant_exact", ProviderSubject: "subject_exact", Event: adminroles.RegisteredEvent{EventID: ShanghaiEventID, Series: "dreamup", Slug: "dreamup-shanghai-2026", DisplayName: "MoonStone DreamUP 上海站 2026", SourceVersion: "worker-v1", AuthoritativeReadAt: now}}
}
func testApprovalKeys(t *testing.T) (*ApprovalKeyring, []ed25519.PrivateKey) {
	t.Helper()
	keys := make([]ApprovalKey, 2)
	private := make([]ed25519.PrivateKey, 2)
	for i, name := range []string{"a", "b"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		private[i] = priv
		keys[i] = ApprovalKey{OperatorUserID: "operator_" + name, KeyID: "key_" + name, PublicKey: base64.RawURLEncoding.EncodeToString(pub)}
	}
	ring, err := NewApprovalKeyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	return ring, private
}
func signTestApproval(t *testing.T, change Change, operator, keyID string, key ed25519.PrivateKey, now time.Time) Approval {
	t.Helper()
	approval := Approval{OperatorUserID: operator, TargetUserID: string(change.TargetUserID), Action: change.Action, Provider: change.Provider, ProviderTenantID: change.ProviderTenantID, ProviderSubject: change.ProviderSubject, Nonce: "nonce-" + operator, ExpiresAt: now.Add(time.Hour), KeyID: keyID}
	payload, err := CanonicalApprovalPayload(change, approval)
	if err != nil {
		t.Fatal(err)
	}
	approval.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))
	return approval
}
