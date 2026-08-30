package wechatonboarding

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
)

type proofStub struct {
	proof wechat.IdentityProof
	err   error
	phone string
}

func (s *proofStub) VerifyOnboarding(_ context.Context, _, phone string) (wechat.IdentityProof, error) {
	s.phone = phone
	return s.proof, s.err
}

type bindingStub struct {
	link identity.IdentityLink
	user identity.User
	err  error
}

func (s *bindingStub) GetIdentityLink(context.Context, string, string, string) (identity.IdentityLink, error) {
	return s.link, s.err
}

func (s *bindingStub) GetByID(context.Context, identity.UserID) (identity.User, error) {
	return s.user, nil
}

type accountStub struct {
	user      identity.User
	snapshot  AccountSnapshot
	findErr   error
	findEmail string
	bind      BindExistingInput
	bindErr   error
	events    *[]string
}

func (s *accountStub) FindByNormalizedEmail(_ context.Context, email string) (AccountSnapshot, error) {
	if s.events != nil {
		*s.events = append(*s.events, "lookup")
	}
	s.findEmail = email
	if s.findErr != nil {
		return AccountSnapshot{}, s.findErr
	}
	if s.snapshot.User.ID != "" {
		return s.snapshot, nil
	}
	user := s.user
	if user.Version <= 0 {
		user.Version = 1
	}
	return AccountSnapshot{User: user, NormalizedEmail: email, Version: user.Version, SecurityEpoch: 1}, nil
}

func (s *accountStub) BindExistingWithWeChat(_ context.Context, input BindExistingInput) (BindExistingResult, error) {
	s.bind = input
	return BindExistingResult{UserID: input.UserID, Linked: true, PhoneAdded: input.Phone != ""}, s.bindErr
}

type passwordStub struct {
	passwordResult auth.AuthenticationResult
	mfaResult      auth.AuthenticationResult
	verifyUser     identity.UserID
	verifyPassword string
	mfaInput       auth.MFAChallengeInput
	revoked        []string
	events         *[]string
}

func (s *passwordStub) VerifyUserPassword(_ context.Context, userID identity.UserID, password string) (auth.AuthenticationResult, error) {
	if s.events != nil {
		*s.events = append(*s.events, "password")
	}
	s.verifyUser, s.verifyPassword = userID, password
	return s.passwordResult, nil
}

func (s *passwordStub) CompleteMFA(_ context.Context, input auth.MFAChallengeInput) (auth.AuthenticationResult, error) {
	if s.events != nil {
		*s.events = append(*s.events, "mfa")
	}
	s.mfaInput = input
	return s.mfaResult, nil
}

func (s *passwordStub) RevokeProviderSession(_ context.Context, reference string) error {
	s.revoked = append(s.revoked, reference)
	return nil
}

type creatorStub struct {
	input  wechatregistration.CreateVerifiedInput
	result registration.CreateResult
	err    error
}

func (s *creatorStub) CreateVerified(_ context.Context, input wechatregistration.CreateVerifiedInput) (registration.CreateResult, error) {
	s.input = input
	return s.result, s.err
}

type memoryChallengeStore struct {
	items    map[string]ChallengeData
	claims   map[string]string
	attempts map[string]int
}

func newMemoryChallengeStore() *memoryChallengeStore {
	return &memoryChallengeStore{items: map[string]ChallengeData{}, claims: map[string]string{}, attempts: map[string]int{}}
}

func (s *memoryChallengeStore) Create(_ context.Context, token string, data ChallengeData, _ time.Duration) error {
	if _, exists := s.items[token]; exists {
		return errors.New("duplicate")
	}
	s.items[token] = data
	return nil
}

func (s *memoryChallengeStore) Claim(_ context.Context, token, claimID string) (ChallengeData, error) {
	data, exists := s.items[token]
	if !exists {
		return ChallengeData{}, ErrChallengeNotFound
	}
	if s.claims[token] != "" {
		return ChallengeData{}, ErrChallengeClaimed
	}
	s.claims[token] = claimID
	return data, nil
}

func (s *memoryChallengeStore) Release(_ context.Context, token, claimID string) error {
	if s.claims[token] != claimID {
		return ErrChallengeNotHeld
	}
	delete(s.claims, token)
	return nil
}

func (s *memoryChallengeStore) Consume(_ context.Context, token, claimID string) error {
	if s.claims[token] != claimID {
		return ErrChallengeNotHeld
	}
	if _, exists := s.items[token]; !exists {
		return ErrChallengeNotFound
	}
	delete(s.items, token)
	delete(s.claims, token)
	delete(s.attempts, token)
	return nil
}

func (s *memoryChallengeStore) IncrementAttempts(_ context.Context, token string, max int) (int, error) {
	if _, exists := s.items[token]; !exists {
		return 0, ErrChallengeNotFound
	}
	s.attempts[token]++
	if s.attempts[token] >= max {
		return s.attempts[token], ErrMaxAttempts
	}
	return s.attempts[token], nil
}

type rateStub struct {
	allowed         bool
	targetDeny      bool
	targetErr       error
	targetRetry     time.Duration
	calls           int
	completionCalls int
	completionIP    string
	completionNet   string
	completionEmail string
	peers           []string
	keys            []string
	limits          []int
	windows         []time.Duration
	events          *[]string
}

func (s *rateStub) CheckMFA(_ context.Context, peer, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	s.calls++
	s.peers = append(s.peers, peer)
	s.keys = append(s.keys, key)
	s.limits = append(s.limits, limit)
	s.windows = append(s.windows, window)
	if s.events != nil {
		*s.events = append(*s.events, "rate:"+peer)
	}
	if peer == targetAccountRatePeer && (s.targetDeny || s.targetErr != nil) {
		return false, s.targetRetry, s.targetErr
	}
	return s.allowed, 0, nil
}

func (s *rateStub) CheckRegistrationCreate(_ context.Context, ip, network, emailHash string, _ registration.CreateRatePolicy) (bool, time.Duration, error) {
	if s.events != nil {
		*s.events = append(*s.events, "completion-rate")
	}
	s.completionCalls++
	s.completionIP, s.completionNet, s.completionEmail = ip, network, emailHash
	return s.allowed, time.Minute, nil
}

func onboardingCompletionRatePolicy() registration.CreateRatePolicy {
	limit := registration.Limit{Max: 5, Window: time.Minute}
	return registration.CreateRatePolicy{
		ClientIP: limit, ClientNet: limit, Email: limit, ClientEmail: limit,
		IPv4NetBits: 24, IPv6NetBits: 64,
	}
}

func serviceForTest(proof *proofStub, bindings *bindingStub, accounts *accountStub, password *passwordStub, creator *creatorStub, store *memoryChallengeStore, rate *rateStub, tokens ...string) *Service {
	index := 0
	return NewService(proof, bindings, accounts, password, creator, store, rate, rate, Config{
		OnboardingTTL: 5 * time.Minute, MFATTL: 3 * time.Minute, MaxAttempts: 3,
		RateLimit: 5, RateWindow: time.Minute, TargetRateLimit: 7, TargetRateWindow: 2 * time.Minute,
		CompletionRatePolicy: onboardingCompletionRatePolicy(),
		Now:                  func() time.Time { return time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC) },
		GenerateToken: func() (string, error) {
			if index >= len(tokens) {
				return "generated-token", nil
			}
			value := tokens[index]
			index++
			return value, nil
		},
	})
}

func TestBeginRestoresOnlyExistingActiveBinding(t *testing.T) {
	userID := identity.UserID("user_existing")
	proof := &proofStub{proof: wechat.IdentityProof{TenantID: "app", Subject: "open-id"}}
	bindings := &bindingStub{link: identity.IdentityLink{UserID: userID}, user: identity.User{ID: userID, Status: identity.UserStatusActive}}
	service := serviceForTest(proof, bindings, &accountStub{}, &passwordStub{}, &creatorStub{}, newMemoryChallengeStore(), &rateStub{allowed: true})
	result, err := service.Begin(context.Background(), BeginInput{LoginCode: "login-code", PhoneCode: " bad"})
	if err != nil || result.Status != StatusAuthenticated || result.UserID != userID || result.OnboardingToken != "" {
		t.Fatalf("Begin = %#v, %v", result, err)
	}
	if proof.phone != " bad" {
		t.Fatalf("optional phone code was not delegated to best-effort verifier: %q", proof.phone)
	}
}

func TestBeginReissuesOnboardingForExactPendingWeChatReservation(t *testing.T) {
	userID := identity.UserID("user_pending")
	proof := &proofStub{proof: wechat.IdentityProof{TenantID: "app", Subject: "open-id", Phone: "+8613800138000"}}
	bindings := &bindingStub{
		link: identity.IdentityLink{UserID: userID},
		user: identity.User{ID: userID, Status: identity.UserStatusPending, Email: "pending@example.com", EmailVerified: false},
	}
	store := newMemoryChallengeStore()
	service := serviceForTest(proof, bindings, &accountStub{}, &passwordStub{}, &creatorStub{}, store, &rateStub{allowed: true}, "pending-onboarding-token")
	result, err := service.Begin(context.Background(), BeginInput{LoginCode: "login-code", PhoneCode: "phone-code"})
	if err != nil || result.Status != StatusOnboardingRequired || result.OnboardingToken != "pending-onboarding-token" {
		t.Fatalf("Begin = %#v, %v", result, err)
	}
	challenge := store.items[result.OnboardingToken]
	if challenge.TargetUserID != userID || challenge.Subject != "open-id" || challenge.Phone != "+8613800138000" {
		t.Fatalf("pending challenge = %#v", challenge)
	}
}

func TestCompleteExistingUsesStableUserIDAndAcceptsHistoricPasswordShape(t *testing.T) {
	userID := identity.UserID("user_existing")
	store := newMemoryChallengeStore()
	store.items["onboarding-token"] = ChallengeData{Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding, TenantID: "app", Subject: "open-id", Phone: "+8613800138000"}
	accounts := &accountStub{user: identity.User{ID: userID, Status: identity.UserStatusActive}}
	password := &passwordStub{passwordResult: auth.AuthenticationResult{Status: auth.StatusAuthenticated, UserID: userID, Provider: "zitadel", ProviderSessionReference: "provider-session", AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword}}}
	service := serviceForTest(&proofStub{}, &bindingStub{}, accounts, password, &creatorStub{}, store, &rateStub{allowed: true}, "claim-id")
	result, err := service.Complete(context.Background(), CompleteInput{
		OnboardingToken: "onboarding-token", Email: "EXISTING@EXAMPLE.COM", Password: "old",
		AcceptedTerms: true, ClientIP: "127.0.0.1",
	})
	if err != nil || result.Status != StatusAuthenticated {
		t.Fatalf("Complete = %#v, %v", result, err)
	}
	if accounts.findEmail != "existing@example.com" || password.verifyUser != userID || password.verifyPassword != "old" {
		t.Fatalf("lookup/password target = %q %q %q", accounts.findEmail, password.verifyUser, password.verifyPassword)
	}
	if accounts.bind.UserID != userID || accounts.bind.Subject != "open-id" || accounts.bind.Phone != "+8613800138000" || accounts.bind.NormalizedEmail != "existing@example.com" || accounts.bind.ExpectedVersion != 1 || accounts.bind.ExpectedSecurityEpoch != 1 {
		t.Fatalf("bind input = %#v", accounts.bind)
	}
	if _, exists := store.items["onboarding-token"]; exists {
		t.Fatal("successful onboarding token was not consumed")
	}
}

func TestCompleteExistingConsumesProofAndRevokesSessionWhenAuthoritySnapshotIsStale(t *testing.T) {
	userID := identity.UserID("user_existing")
	store := newMemoryChallengeStore()
	store.items["onboarding-token"] = ChallengeData{Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding, TenantID: "app", Subject: "open-id"}
	accounts := &accountStub{
		snapshot: AccountSnapshot{
			User:            identity.User{ID: userID, Status: identity.UserStatusActive, Version: 7},
			NormalizedEmail: "existing@example.com", Version: 7, SecurityEpoch: 4,
		},
		bindErr: ErrAccountChanged,
	}
	password := &passwordStub{passwordResult: auth.AuthenticationResult{
		Status: auth.StatusAuthenticated, UserID: userID,
		ProviderSessionReference: "provider-session-stale",
	}}
	service := serviceForTest(&proofStub{}, &bindingStub{}, accounts, password, &creatorStub{}, store, &rateStub{allowed: true}, "claim-id")

	_, err := service.Complete(context.Background(), CompleteInput{
		OnboardingToken: "onboarding-token", Email: "existing@example.com", Password: "password",
		AcceptedTerms: true, ClientIP: "127.0.0.1",
	})
	if !errors.Is(err, ErrAuthenticationFail) {
		t.Fatalf("stale authority error = %v, want ErrAuthenticationFail", err)
	}
	if _, exists := store.items["onboarding-token"]; exists || len(password.revoked) != 1 || password.revoked[0] != "provider-session-stale" {
		t.Fatalf("stale proof cleanup: exists=%v revoked=%#v", exists, password.revoked)
	}
	if accounts.bind.NormalizedEmail != "existing@example.com" || accounts.bind.ExpectedVersion != 7 || accounts.bind.ExpectedSecurityEpoch != 4 {
		t.Fatalf("stale CAS input = %#v", accounts.bind)
	}
}

func TestCompleteExistingWrongPasswordReturnsStableSentinelAfterClaimAndRate(t *testing.T) {
	userID := identity.UserID("user_existing")
	store := newMemoryChallengeStore()
	store.items["onboarding-token"] = ChallengeData{Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding, TenantID: "app", Subject: "open-id"}
	rate := &rateStub{allowed: true}
	accounts := &accountStub{user: identity.User{ID: userID, Status: identity.UserStatusActive}}
	password := &passwordStub{passwordResult: auth.AuthenticationResult{Status: auth.StatusInvalidCredentials}}
	service := serviceForTest(&proofStub{}, &bindingStub{}, accounts, password, &creatorStub{}, store, rate, "claim-id")
	_, err := service.Complete(context.Background(), CompleteInput{OnboardingToken: "onboarding-token", Email: "existing@example.com", Password: "wrong", AcceptedTerms: true, ClientIP: "127.0.0.1"})
	if !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("error = %v, want ErrPasswordMismatch", err)
	}
	if rate.calls != 3 || rate.completionCalls != 1 || rate.completionEmail == "existing@example.com" || len(rate.completionEmail) != 64 || store.attempts["onboarding-token"] != 1 || store.claims["onboarding-token"] != "" {
		t.Fatalf("rate/attempt/release = token:%d completion:%d email:%q attempts:%d claim:%q", rate.calls, rate.completionCalls, rate.completionEmail, store.attempts["onboarding-token"], store.claims["onboarding-token"])
	}
	if rate.peers[1] != "wechat-subject" || len(rate.keys[1]) != 64 || strings.Contains(rate.keys[1], "open-id") {
		t.Fatalf("subject limiter leaked provider identity: peers=%#v keys=%#v", rate.peers, rate.keys)
	}
	if rate.peers[2] != targetAccountRatePeer || rate.keys[2] != session.HashToken(targetAccountRateDomain+string(userID)) || strings.Contains(rate.keys[2], string(userID)) {
		t.Fatalf("target limiter is not stable and opaque: peers=%#v keys=%#v", rate.peers, rate.keys)
	}
	if accounts.bind.UserID != "" {
		t.Fatalf("wrong password linked account: %#v", accounts.bind)
	}
}

func TestTargetAccountBucketIsStableAcrossSubjectIPAndEmail(t *testing.T) {
	userID := identity.UserID("user_target_1")
	store := newMemoryChallengeStore()
	store.items["token-one"] = ChallengeData{Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding, TenantID: "app", Subject: "subject-one"}
	store.items["token-two"] = ChallengeData{Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding, TenantID: "app", Subject: "subject-two"}
	rate := &rateStub{allowed: true}
	accounts := &accountStub{user: identity.User{ID: userID, Status: identity.UserStatusActive}}
	password := &passwordStub{passwordResult: auth.AuthenticationResult{Status: auth.StatusInvalidCredentials}}
	service := serviceForTest(&proofStub{}, &bindingStub{}, accounts, password, &creatorStub{}, store, rate, "claim-one", "claim-two")

	for _, input := range []CompleteInput{
		{OnboardingToken: "token-one", Email: "first@example.com", Password: "wrong", AcceptedTerms: true, ClientIP: "203.0.113.10", ClientNetwork: "203.0.113.0/24"},
		{OnboardingToken: "token-two", Email: "second@example.com", Password: "wrong", AcceptedTerms: true, ClientIP: "198.51.100.20", ClientNetwork: "198.51.100.0/24"},
	} {
		if _, err := service.Complete(context.Background(), input); !errors.Is(err, ErrPasswordMismatch) {
			t.Fatalf("Complete(%q) error = %v, want ErrPasswordMismatch", input.Email, err)
		}
	}

	if len(rate.peers) != 6 || rate.peers[2] != targetAccountRatePeer || rate.peers[5] != targetAccountRatePeer {
		t.Fatalf("target limiter calls = peers %#v", rate.peers)
	}
	wantKey := session.HashToken(targetAccountRateDomain + string(userID))
	if rate.keys[2] != wantKey || rate.keys[5] != wantKey || len(wantKey) != 64 || strings.Contains(wantKey, string(userID)) {
		t.Fatalf("target keys are not shared and opaque: %#v", rate.keys)
	}
	if rate.limits[2] != 7 || rate.limits[5] != 7 || rate.windows[2] != 2*time.Minute || rate.windows[5] != 2*time.Minute {
		t.Fatalf("target policy = limits %#v windows %#v", rate.limits, rate.windows)
	}
}

func TestTargetAccountRateLimiterFailsClosedBeforePasswordWithRetryHint(t *testing.T) {
	for _, test := range []struct {
		name      string
		targetErr error
		retry     time.Duration
		wantRetry time.Duration
	}{
		{name: "backend error", targetErr: errors.New("rate backend unavailable"), wantRetry: 2 * time.Minute},
		{name: "limit reached", retry: 37 * time.Second, wantRetry: 37 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			store := newMemoryChallengeStore()
			store.items["onboarding-token"] = ChallengeData{Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding, TenantID: "app", Subject: "open-id"}
			rate := &rateStub{allowed: true, targetDeny: test.targetErr == nil, targetErr: test.targetErr, targetRetry: test.retry, events: &events}
			accounts := &accountStub{user: identity.User{ID: "user_existing", Status: identity.UserStatusActive}, events: &events}
			password := &passwordStub{events: &events}
			service := serviceForTest(&proofStub{}, &bindingStub{}, accounts, password, &creatorStub{}, store, rate, "claim-id")

			_, err := service.Complete(context.Background(), CompleteInput{
				OnboardingToken: "onboarding-token", Email: "existing@example.com", Password: "password",
				AcceptedTerms: true, ClientIP: "127.0.0.1", ClientNetwork: "127.0.0.0/8",
			})
			var limitErr *RateLimitError
			if !errors.Is(err, ErrRateLimited) || !errors.As(err, &limitErr) || limitErr.RetryAfter != test.wantRetry {
				t.Fatalf("rate error = %#v, want retry %v", err, test.wantRetry)
			}
			wantOrder := "rate:127.0.0.1,rate:wechat-subject,completion-rate,lookup,rate:" + targetAccountRatePeer
			if got := strings.Join(events, ","); got != wantOrder {
				t.Fatalf("call order = %q, want %q", got, wantOrder)
			}
			if password.verifyUser != "" || store.claims["onboarding-token"] != "" || store.attempts["onboarding-token"] != 0 {
				t.Fatalf("target failure reached password or consumed an attempt: user=%q claim=%q attempts=%d", password.verifyUser, store.claims["onboarding-token"], store.attempts["onboarding-token"])
			}
		})
	}
}

func TestMFACompletionRechecksTargetBucketBeforeProvider(t *testing.T) {
	events := []string{}
	userID := identity.UserID("user_existing")
	store := newMemoryChallengeStore()
	store.items["mfa-token"] = ChallengeData{
		Purpose: MFAChallengePurpose, Kind: ChallengeKindMFA,
		TenantID: "app", Subject: "open-id", TargetUserID: userID, NormalizedEmail: "existing@example.com",
		ExpectedVersion: 1, ExpectedSecurityEpoch: 1, ProviderSessionID: "provider-mfa",
		AvailableMethods: []auth.MFAMethod{auth.MFAMethodTOTP},
	}
	rate := &rateStub{allowed: true, events: &events}
	password := &passwordStub{mfaResult: auth.AuthenticationResult{Status: auth.StatusInvalidCredentials}, events: &events}
	service := serviceForTest(&proofStub{}, &bindingStub{}, &accountStub{}, password, &creatorStub{}, store, rate, "claim-mfa")

	_, err := service.CompleteMFA(context.Background(), MFAInput{MFAToken: "mfa-token", Method: auth.MFAMethodTOTP, Code: "123456", ClientIP: "192.0.2.10"})
	if !errors.Is(err, ErrAuthenticationFail) {
		t.Fatalf("CompleteMFA error = %v, want ErrAuthenticationFail", err)
	}
	wantOrder := "rate:192.0.2.10,rate:wechat-subject,rate:" + targetAccountRatePeer + ",mfa"
	if got := strings.Join(events, ","); got != wantOrder {
		t.Fatalf("MFA call order = %q, want %q", got, wantOrder)
	}
	if len(rate.keys) != 3 || rate.keys[2] != session.HashToken(targetAccountRateDomain+string(userID)) || password.mfaInput.ProviderSessionID != "provider-mfa" {
		t.Fatalf("MFA target limiter/provider input = keys %#v input %#v", rate.keys, password.mfaInput)
	}
}

func TestCompleteDoesNotConsumeGlobalRegistrationBucketsBeforeChallengeClaim(t *testing.T) {
	rate := &rateStub{allowed: true}
	accounts := &accountStub{}
	service := serviceForTest(&proofStub{}, &bindingStub{}, accounts, &passwordStub{}, &creatorStub{}, newMemoryChallengeStore(), rate, "claim-id")
	_, err := service.Complete(context.Background(), CompleteInput{
		OnboardingToken: "missing-token", Email: "victim@example.com", Password: "wrong",
		AcceptedTerms: true, ClientIP: "203.0.113.10", ClientNetwork: "203.0.113.0/24",
	})
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("error = %v, want ErrChallengeNotFound", err)
	}
	if rate.completionCalls != 0 || accounts.findEmail != "" {
		t.Fatalf("invalid challenge consumed global bucket or queried email: calls=%d email=%q", rate.completionCalls, accounts.findEmail)
	}
}

func TestCompleteNewAccountAppliesStrongPolicyAndForwardsVerifiedProof(t *testing.T) {
	store := newMemoryChallengeStore()
	store.items["onboarding-token"] = ChallengeData{Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding, TenantID: "app", Subject: "open-id"}
	creator := &creatorStub{result: registration.CreateResult{RegistrationToken: "registration-token", ExpiresAt: time.Now().Add(time.Hour)}}
	service := serviceForTest(&proofStub{}, &bindingStub{}, &accountStub{findErr: identity.ErrUserNotFound}, &passwordStub{}, creator, store, &rateStub{allowed: true}, "claim-id")
	result, err := service.Complete(context.Background(), CompleteInput{
		OnboardingToken: "onboarding-token", Email: "new@example.com", Password: "Strong-Password-123!",
		Username: "new_user", DisplayName: "New User", AcceptedTerms: true, RequestID: "request-1", ClientIP: "127.0.0.1",
	})
	if err != nil || result.Status != StatusVerificationNeeded || result.RegistrationToken != "registration-token" {
		t.Fatalf("Complete = %#v, %v", result, err)
	}
	if creator.input.Proof.TenantID != "app" || creator.input.Proof.Subject != "open-id" || creator.input.Proof.Phone != "" {
		t.Fatalf("verified proof = %#v", creator.input.Proof)
	}

	store.items["weak-token"] = ChallengeData{Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding, TenantID: "app", Subject: "open-id-2"}
	_, err = service.Complete(context.Background(), CompleteInput{OnboardingToken: "weak-token", Email: "new2@example.com", Password: "old", Username: "new_user2", DisplayName: "New", AcceptedTerms: true, ClientIP: "127.0.0.1"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("weak new password error = %v", err)
	}
}

func TestCompleteReconcilesOnlyThePendingUserBoundIntoChallenge(t *testing.T) {
	userID := identity.UserID("user_pending")
	store := newMemoryChallengeStore()
	store.items["pending-token"] = ChallengeData{
		Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding,
		TenantID: "app", Subject: "open-id", Phone: "+8613800138000", TargetUserID: userID,
	}
	creator := &creatorStub{result: registration.CreateResult{RegistrationToken: "registration-token", ExpiresAt: time.Now().Add(time.Hour)}}
	accounts := &accountStub{user: identity.User{ID: userID, Status: identity.UserStatusPending, Email: "pending@example.com"}}
	service := serviceForTest(&proofStub{}, &bindingStub{}, accounts, &passwordStub{}, creator, store, &rateStub{allowed: true}, "claim-id")
	result, err := service.Complete(context.Background(), CompleteInput{
		OnboardingToken: "pending-token", Email: "pending@example.com", Password: "Strong-Password-123!",
		Username: "pending_user", DisplayName: "Pending User", AcceptedTerms: true, RequestID: "request-1", ClientIP: "127.0.0.1",
	})
	if err != nil || result.Status != StatusVerificationNeeded {
		t.Fatalf("Complete = %#v, %v", result, err)
	}
	if creator.input.Proof.Subject != "open-id" || creator.input.Registration.Email != "pending@example.com" || creator.input.ExpectedUserID != string(userID) {
		t.Fatalf("reconciliation input = %#v", creator.input)
	}

	store.items["mismatch-token"] = ChallengeData{
		Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding,
		TenantID: "app", Subject: "open-id", TargetUserID: userID,
	}
	accounts.user = identity.User{ID: identity.UserID("different_pending"), Status: identity.UserStatusPending, Email: "pending@example.com"}
	_, err = service.Complete(context.Background(), CompleteInput{
		OnboardingToken: "mismatch-token", Email: "pending@example.com", Password: "Strong-Password-123!",
		Username: "pending_user", DisplayName: "Pending User", AcceptedTerms: true, ClientIP: "127.0.0.1",
	})
	if !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("mismatched pending user error = %v", err)
	}
}

func TestMFAChallengeBindsTargetAndRejectsCrossUserCompletion(t *testing.T) {
	userID := identity.UserID("user_existing")
	store := newMemoryChallengeStore()
	store.items["onboarding-token"] = ChallengeData{Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding, TenantID: "app", Subject: "open-id"}
	accounts := &accountStub{user: identity.User{ID: userID, Status: identity.UserStatusActive}}
	password := &passwordStub{
		passwordResult: auth.AuthenticationResult{Status: auth.StatusMFARequired, Provider: "zitadel", ProviderSessionID: "provider-mfa", AvailableMethods: []auth.MFAMethod{auth.MFAMethodTOTP}, PasskeyRequestOptions: json.RawMessage(`{"challenge":"x"}`)},
		mfaResult:      auth.AuthenticationResult{Status: auth.StatusAuthenticated, UserID: "user_attacker", ProviderSessionReference: "provider-session"},
	}
	service := serviceForTest(&proofStub{}, &bindingStub{}, accounts, password, &creatorStub{}, store, &rateStub{allowed: true}, "claim-onboarding", "mfa-token", "claim-mfa")
	result, err := service.Complete(context.Background(), CompleteInput{OnboardingToken: "onboarding-token", Email: "existing@example.com", Password: "password", AcceptedTerms: true, ClientIP: "127.0.0.1"})
	if err != nil || result.Status != StatusMFARequired || result.MFAToken != "mfa-token" {
		t.Fatalf("Complete MFA begin = %#v, %v", result, err)
	}
	challenge := store.items["mfa-token"]
	if challenge.TargetUserID != userID || challenge.ProviderSessionID != "provider-mfa" || challenge.Purpose != MFAChallengePurpose || challenge.NormalizedEmail != "existing@example.com" || challenge.ExpectedVersion != 1 || challenge.ExpectedSecurityEpoch != 1 {
		t.Fatalf("MFA challenge = %#v", challenge)
	}
	_, err = service.CompleteMFA(context.Background(), MFAInput{MFAToken: "mfa-token", Method: auth.MFAMethodTOTP, Code: "123456", ClientIP: "127.0.0.1"})
	if !errors.Is(err, ErrAuthenticationFail) {
		t.Fatalf("cross-user MFA error = %v", err)
	}
	if accounts.bind.UserID != "" || len(password.revoked) == 0 {
		t.Fatalf("cross-user MFA bind/revoke = %#v %#v", accounts.bind, password.revoked)
	}
}

func TestMFACompletionConsumesChallengeAndRevokesSessionWhenAuthoritySnapshotIsStale(t *testing.T) {
	userID := identity.UserID("user_existing")
	store := newMemoryChallengeStore()
	store.items["onboarding-token"] = ChallengeData{Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding, TenantID: "app", Subject: "open-id"}
	accounts := &accountStub{snapshot: AccountSnapshot{
		User:            identity.User{ID: userID, Status: identity.UserStatusActive, Version: 9},
		NormalizedEmail: "existing@example.com", Version: 9, SecurityEpoch: 6,
	}}
	password := &passwordStub{
		passwordResult: auth.AuthenticationResult{Status: auth.StatusMFARequired, Provider: "zitadel", ProviderSessionID: "provider-mfa", AvailableMethods: []auth.MFAMethod{auth.MFAMethodTOTP}},
		mfaResult:      auth.AuthenticationResult{Status: auth.StatusAuthenticated, UserID: userID, ProviderSessionReference: "provider-session-stale"},
	}
	service := serviceForTest(&proofStub{}, &bindingStub{}, accounts, password, &creatorStub{}, store, &rateStub{allowed: true}, "claim-onboarding", "mfa-token", "claim-mfa")
	if _, err := service.Complete(context.Background(), CompleteInput{OnboardingToken: "onboarding-token", Email: "existing@example.com", Password: "password", AcceptedTerms: true, ClientIP: "127.0.0.1"}); err != nil {
		t.Fatalf("begin MFA: %v", err)
	}
	accounts.bindErr = ErrAccountChanged

	_, err := service.CompleteMFA(context.Background(), MFAInput{MFAToken: "mfa-token", Method: auth.MFAMethodTOTP, Code: "123456", ClientIP: "127.0.0.1"})
	if !errors.Is(err, ErrAuthenticationFail) {
		t.Fatalf("stale MFA authority error = %v, want ErrAuthenticationFail", err)
	}
	if _, exists := store.items["mfa-token"]; exists || len(password.revoked) != 1 || password.revoked[0] != "provider-session-stale" {
		t.Fatalf("stale MFA cleanup: exists=%v revoked=%#v", exists, password.revoked)
	}
	if accounts.bind.NormalizedEmail != "existing@example.com" || accounts.bind.ExpectedVersion != 9 || accounts.bind.ExpectedSecurityEpoch != 6 {
		t.Fatalf("MFA CAS input = %#v", accounts.bind)
	}
}

func TestMFACompletionRejectsChallengeWithoutAuthoritySnapshot(t *testing.T) {
	store := newMemoryChallengeStore()
	store.items["mfa-token"] = ChallengeData{
		Purpose: MFAChallengePurpose, Kind: ChallengeKindMFA,
		TenantID: "app", Subject: "open-id", TargetUserID: "user_existing",
		ProviderSessionID: "provider-mfa", AvailableMethods: []auth.MFAMethod{auth.MFAMethodTOTP},
	}
	password := &passwordStub{}
	service := serviceForTest(&proofStub{}, &bindingStub{}, &accountStub{}, password, &creatorStub{}, store, &rateStub{allowed: true}, "claim-mfa")
	_, err := service.CompleteMFA(context.Background(), MFAInput{MFAToken: "mfa-token", Method: auth.MFAMethodTOTP, Code: "123456", ClientIP: "127.0.0.1"})
	if !errors.Is(err, ErrAuthenticationFail) {
		t.Fatalf("invalid MFA snapshot error = %v", err)
	}
	if _, exists := store.items["mfa-token"]; exists || len(password.revoked) != 1 || password.revoked[0] != "provider-mfa" || password.mfaInput.ProviderSessionID != "" {
		t.Fatalf("invalid MFA snapshot cleanup: exists=%v revoked=%#v mfa=%#v", exists, password.revoked, password.mfaInput)
	}
}

func TestInvalidChallengeNeverReachesRateOrEmailLookup(t *testing.T) {
	rate := &rateStub{allowed: true}
	accounts := &accountStub{}
	service := serviceForTest(&proofStub{}, &bindingStub{}, accounts, &passwordStub{}, &creatorStub{}, newMemoryChallengeStore(), rate, "claim-id")
	_, err := service.Complete(context.Background(), CompleteInput{OnboardingToken: "missing-token", Email: "existing@example.com", Password: "password", AcceptedTerms: true, ClientIP: "127.0.0.1"})
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("error = %v", err)
	}
	if rate.calls != 0 || accounts.findEmail != "" {
		t.Fatalf("invalid token reached rate/lookup: calls=%d email=%q", rate.calls, accounts.findEmail)
	}
}
