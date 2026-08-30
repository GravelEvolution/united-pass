package wechatonboarding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
)

const (
	maxChallengeTokenBytes  = 512
	targetAccountRatePeer   = "wechat-onboarding-target"
	targetAccountRateDomain = "wechat-onboarding-target/v1\x00"
)

type Config struct {
	OnboardingTTL        time.Duration
	MFATTL               time.Duration
	MaxAttempts          int
	RateLimit            int
	RateWindow           time.Duration
	TargetRateLimit      int
	TargetRateWindow     time.Duration
	CompletionRatePolicy registration.CreateRatePolicy
	Now                  func() time.Time
	GenerateToken        func() (string, error)
}

type Service struct {
	verifier       ProofVerifier
	bindings       BindingReader
	accounts       AccountRepository
	password       PasswordAuthenticator
	creator        NewAccountCreator
	store          ChallengeStore
	rate           RateChecker
	completionRate CompletionRateChecker
	cfg            Config
}

func NewService(verifier ProofVerifier, bindings BindingReader, accounts AccountRepository, password PasswordAuthenticator, creator NewAccountCreator, store ChallengeStore, rate RateChecker, completionRate CompletionRateChecker, cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.GenerateToken == nil {
		cfg.GenerateToken = session.GenerateToken
	}
	// Preserve existing callers under the configured onboarding attempt policy
	// until bootstrap exposes independent target-account tuning. The target
	// account still receives its own global, stable Redis bucket.
	if cfg.TargetRateLimit <= 0 {
		cfg.TargetRateLimit = cfg.RateLimit
	}
	if cfg.TargetRateWindow <= 0 {
		cfg.TargetRateWindow = cfg.RateWindow
	}
	return &Service{verifier: verifier, bindings: bindings, accounts: accounts, password: password, creator: creator, store: store, rate: rate, completionRate: completionRate, cfg: cfg}
}

// Begin proves wx.login on the server. An optional phone code is best effort:
// its failure produces a proof with no phone, never a client-visible second
// authorization stage. Already-linked active users are restored directly;
// every other identity receives a short-lived single-use onboarding token.
func (s *Service) Begin(ctx context.Context, input BeginInput) (BeginResult, error) {
	if !s.ready() {
		return BeginResult{}, ErrUnavailable
	}
	if wechat.ValidateCode(input.LoginCode) != nil {
		return BeginResult{}, ErrInvalidInput
	}
	proof, err := s.verifier.VerifyOnboarding(ctx, input.LoginCode, input.PhoneCode)
	if err != nil {
		if errors.Is(err, wechat.ErrInvalidCode) || errors.Is(err, wechat.ErrRejected) {
			return BeginResult{}, ErrInvalidInput
		}
		return BeginResult{}, ErrUnavailable
	}
	if !validProof(proof) {
		return BeginResult{}, ErrUnavailable
	}

	var pendingUserID identity.UserID
	link, err := s.bindings.GetIdentityLink(ctx, wechat.ProviderName, proof.TenantID, proof.Subject)
	if err == nil {
		user, userErr := s.bindings.GetByID(ctx, link.UserID)
		if userErr != nil {
			if errors.Is(userErr, identity.ErrUserNotFound) {
				return BeginResult{}, ErrAccountInactive
			}
			return BeginResult{}, ErrUnavailable
		}
		if user.ID == "" {
			return BeginResult{}, ErrAccountInactive
		}
		switch {
		case user.Status.CanAuthenticate():
			return BeginResult{Status: StatusAuthenticated, UserID: user.ID}, nil
		case user.Status == identity.UserStatusPending && !user.EmailVerified:
			// A previous provider or Redis failure may have committed only the
			// pending reservation. Re-issuing a challenge for the exact linked
			// subject lets ReservePendingWithWeChat reconcile that same user ID.
			pendingUserID = user.ID
		default:
			return BeginResult{}, ErrAccountInactive
		}
	}
	if err != nil && !errors.Is(err, identity.ErrUserNotFound) {
		return BeginResult{}, ErrUnavailable
	}

	token, err := s.cfg.GenerateToken()
	if err != nil || !validRawToken(token) {
		return BeginResult{}, ErrUnavailable
	}
	now := s.cfg.Now().UTC()
	challenge := ChallengeData{
		Purpose: ChallengePurpose, Kind: ChallengeKindOnboarding,
		TenantID: proof.TenantID, Subject: proof.Subject, Phone: proof.Phone,
		TargetUserID: pendingUserID,
		CreatedAt:    now,
	}
	if err := s.store.Create(ctx, token, challenge, s.cfg.OnboardingTTL); err != nil {
		return BeginResult{}, ErrUnavailable
	}
	return BeginResult{Status: StatusOnboardingRequired, OnboardingToken: token, ExpiresAt: now.Add(s.cfg.OnboardingTTL)}, nil
}

// Complete first claims and rate-limits a valid onboarding token, then looks
// up the normalized email. Existing accounts use their stable user ID for
// password verification; legacy passwords are intentionally not subjected to
// the new-account strength policy. New emails alone pass ValidateCreate.
func (s *Service) Complete(ctx context.Context, input CompleteInput) (CompleteResult, error) {
	if !s.ready() {
		return CompleteResult{}, ErrUnavailable
	}
	normalizedEmail, err := validateCommonComplete(input)
	if err != nil {
		return CompleteResult{}, err
	}
	claimID, challenge, err := s.claimAndRate(ctx, input.OnboardingToken, input.ClientIP, ChallengeKindOnboarding)
	if err != nil {
		return CompleteResult{}, err
	}
	release := true
	defer func() {
		if release {
			_ = s.store.Release(context.WithoutCancel(ctx), input.OnboardingToken, claimID)
		}
	}()
	if err := s.checkCompletionRate(ctx, input.ClientIP, input.ClientNetwork, normalizedEmail); err != nil {
		return CompleteResult{}, err
	}

	snapshot, lookupErr := s.accounts.FindByNormalizedEmail(ctx, normalizedEmail)
	switch {
	case lookupErr == nil:
		user := snapshot.User
		if challenge.TargetUserID != "" {
			if user.ID != challenge.TargetUserID || user.Status != identity.UserStatusPending || user.EmailVerified {
				_ = s.store.Consume(context.WithoutCancel(ctx), input.OnboardingToken, claimID)
				release = false
				return CompleteResult{}, ErrIdentityConflict
			}
			result, createErr := s.completePendingRegistration(ctx, input.OnboardingToken, claimID, challenge, input, normalizedEmail)
			if createErr == nil {
				release = false
			}
			return result, createErr
		}
		result, completeErr := s.completeExisting(ctx, input.OnboardingToken, claimID, challenge, snapshot, normalizedEmail, input.Password)
		if completeErr == nil || errors.Is(completeErr, ErrPasswordMismatch) || errors.Is(completeErr, ErrMaxAttempts) || terminalBindingError(completeErr) {
			release = false // success/credential failure helpers consumed or released explicitly
		}
		return result, completeErr
	case errors.Is(lookupErr, identity.ErrUserNotFound):
		if challenge.TargetUserID != "" {
			_ = s.store.Consume(context.WithoutCancel(ctx), input.OnboardingToken, claimID)
			release = false
			return CompleteResult{}, ErrIdentityConflict
		}
		result, createErr := s.completePendingRegistration(ctx, input.OnboardingToken, claimID, challenge, input, normalizedEmail)
		if createErr == nil {
			release = false
		}
		return result, createErr
	case errors.Is(lookupErr, ErrEmailAmbiguous):
		return CompleteResult{}, ErrEmailAmbiguous
	default:
		return CompleteResult{}, ErrUnavailable
	}
}

func (s *Service) completePendingRegistration(ctx context.Context, rawToken, claimID string, challenge ChallengeData, input CompleteInput, normalizedEmail string) (CompleteResult, error) {
	// New-account validation happens only after the unique-email lookup so
	// historic passwords remain valid on the active-account merge branch.
	registrationInput := registration.CreateInput{
		Username: input.Username, DisplayName: input.DisplayName, Email: normalizedEmail,
		Password: input.Password, AcceptedTerms: input.AcceptedTerms, RequestID: input.RequestID,
	}
	if err := registration.ValidateCreate(registrationInput); err != nil {
		return CompleteResult{}, ErrInvalidInput
	}
	created, err := s.creator.CreateVerified(ctx, wechatregistration.CreateVerifiedInput{
		Registration:   registrationInput,
		Proof:          wechat.IdentityProof{TenantID: challenge.TenantID, Subject: challenge.Subject, Phone: challenge.Phone},
		ExpectedUserID: string(challenge.TargetUserID),
	})
	if err != nil {
		if errors.Is(err, registration.ErrInvalidInput) {
			return CompleteResult{}, ErrInvalidInput
		}
		if errors.Is(err, registration.ErrConflict) {
			return CompleteResult{}, ErrIdentityConflict
		}
		return CompleteResult{}, ErrUnavailable
	}
	if err := s.store.Consume(ctx, rawToken, claimID); err != nil {
		return CompleteResult{}, ErrUnavailable
	}
	return CompleteResult{Status: StatusVerificationNeeded, RegistrationToken: created.RegistrationToken, ExpiresAt: created.ExpiresAt}, nil
}

func (s *Service) completeExisting(ctx context.Context, rawToken, claimID string, challenge ChallengeData, snapshot AccountSnapshot, normalizedEmail, password string) (CompleteResult, error) {
	user := snapshot.User
	if user.ID == "" || !user.Status.CanAuthenticate() {
		_ = s.store.Consume(context.WithoutCancel(ctx), rawToken, claimID)
		return CompleteResult{}, ErrAccountInactive
	}
	if snapshot.NormalizedEmail != normalizedEmail || snapshot.Version <= 0 || snapshot.SecurityEpoch <= 0 || user.Version != snapshot.Version {
		_ = s.store.Consume(context.WithoutCancel(ctx), rawToken, claimID)
		return CompleteResult{}, ErrAuthenticationFail
	}
	if err := s.checkTargetAccountRate(ctx, user.ID); err != nil {
		return CompleteResult{}, err
	}
	verified, err := s.password.VerifyUserPassword(ctx, user.ID, password)
	if err != nil {
		return CompleteResult{}, ErrUnavailable
	}
	switch verified.Status {
	case auth.StatusAuthenticated:
		if verified.UserID != user.ID {
			s.revoke(ctx, verified.ProviderSessionReference)
			_ = s.store.Consume(context.WithoutCancel(ctx), rawToken, claimID)
			return CompleteResult{}, ErrAuthenticationFail
		}
		bindingProof := challenge
		bindingProof.TargetUserID = user.ID
		bindingProof.NormalizedEmail = snapshot.NormalizedEmail
		bindingProof.ExpectedVersion = snapshot.Version
		bindingProof.ExpectedSecurityEpoch = snapshot.SecurityEpoch
		if err := s.bindExisting(ctx, user.ID, bindingProof); err != nil {
			s.revoke(ctx, verified.ProviderSessionReference)
			if terminalBindingError(err) {
				_ = s.store.Consume(context.WithoutCancel(ctx), rawToken, claimID)
			}
			return CompleteResult{}, err
		}
		if err := s.store.Consume(ctx, rawToken, claimID); err != nil {
			s.revoke(ctx, verified.ProviderSessionReference)
			return CompleteResult{}, ErrUnavailable
		}
		return CompleteResult{Status: StatusAuthenticated, Authentication: verified}, nil

	case auth.StatusMFARequired:
		if verified.ProviderSessionID == "" || len(verified.AvailableMethods) == 0 {
			_ = s.store.Consume(context.WithoutCancel(ctx), rawToken, claimID)
			return CompleteResult{}, ErrAuthenticationFail
		}
		mfaToken, err := s.cfg.GenerateToken()
		if err != nil || !validRawToken(mfaToken) {
			s.revoke(ctx, verified.ProviderSessionID)
			return CompleteResult{}, ErrUnavailable
		}
		now := s.cfg.Now().UTC()
		mfaChallenge := ChallengeData{
			Purpose: MFAChallengePurpose, Kind: ChallengeKindMFA,
			TenantID: challenge.TenantID, Subject: challenge.Subject, Phone: challenge.Phone,
			TargetUserID: user.ID, NormalizedEmail: snapshot.NormalizedEmail,
			ExpectedVersion: snapshot.Version, ExpectedSecurityEpoch: snapshot.SecurityEpoch,
			Provider: verified.Provider, ProviderSessionID: verified.ProviderSessionID,
			AvailableMethods:      append([]auth.MFAMethod(nil), verified.AvailableMethods...),
			PasskeyRequestOptions: append([]byte(nil), verified.PasskeyRequestOptions...), CreatedAt: now,
		}
		if err := s.store.Create(ctx, mfaToken, mfaChallenge, s.cfg.MFATTL); err != nil {
			s.revoke(ctx, verified.ProviderSessionID)
			return CompleteResult{}, ErrUnavailable
		}
		if err := s.store.Consume(ctx, rawToken, claimID); err != nil {
			s.revoke(ctx, verified.ProviderSessionID)
			return CompleteResult{}, ErrUnavailable
		}
		return CompleteResult{
			Status: StatusMFARequired, MFAToken: mfaToken,
			AvailableMethods:      append([]auth.MFAMethod(nil), verified.AvailableMethods...),
			PasskeyRequestOptions: append([]byte(nil), verified.PasskeyRequestOptions...),
			ExpiresAt:             now.Add(s.cfg.MFATTL),
		}, nil

	case auth.StatusInvalidCredentials:
		return CompleteResult{}, s.failAttempt(ctx, rawToken, claimID, ErrPasswordMismatch, "")
	case auth.StatusLocked, auth.StatusExpired:
		_ = s.store.Consume(context.WithoutCancel(ctx), rawToken, claimID)
		return CompleteResult{}, ErrAccountInactive
	case auth.StatusProviderUnavailable:
		return CompleteResult{}, ErrUnavailable
	default:
		_ = s.store.Consume(context.WithoutCancel(ctx), rawToken, claimID)
		return CompleteResult{}, ErrAuthenticationFail
	}
}

// CompleteMFA accepts only the dedicated MFA token. The encrypted challenge
// already binds the target account and WeChat proof, so repeating the
// onboarding token would add no security and would complicate single-use
// semantics.
func (s *Service) CompleteMFA(ctx context.Context, input MFAInput) (CompleteResult, error) {
	if !s.ready() || !validMFAInput(input) {
		return CompleteResult{}, ErrInvalidInput
	}
	claimID, challenge, err := s.claimAndRate(ctx, input.MFAToken, input.ClientIP, ChallengeKindMFA)
	if err != nil {
		return CompleteResult{}, err
	}
	release := true
	defer func() {
		if release {
			_ = s.store.Release(context.WithoutCancel(ctx), input.MFAToken, claimID)
		}
	}()
	if challenge.ProviderSessionID == "" || !validBindingSnapshot(challenge.TargetUserID, challenge) || !methodAvailable(challenge.AvailableMethods, input.Method) {
		_ = s.store.Consume(context.WithoutCancel(ctx), input.MFAToken, claimID)
		release = false
		s.revoke(ctx, challenge.ProviderSessionID)
		return CompleteResult{}, ErrAuthenticationFail
	}
	if err := s.checkTargetAccountRate(ctx, challenge.TargetUserID); err != nil {
		return CompleteResult{}, err
	}
	verified, err := s.password.CompleteMFA(ctx, auth.MFAChallengeInput{
		ProviderSessionID: challenge.ProviderSessionID, Method: input.Method,
		Code: input.Code, PasskeyAssertion: input.PasskeyAssertion,
	})
	if err != nil {
		return CompleteResult{}, ErrUnavailable
	}
	switch verified.Status {
	case auth.StatusAuthenticated:
		if verified.UserID != challenge.TargetUserID {
			_ = s.store.Consume(context.WithoutCancel(ctx), input.MFAToken, claimID)
			release = false
			s.revoke(ctx, verified.ProviderSessionReference)
			return CompleteResult{}, ErrAuthenticationFail
		}
		if err := s.bindExisting(ctx, challenge.TargetUserID, challenge); err != nil {
			s.revoke(ctx, verified.ProviderSessionReference)
			if terminalBindingError(err) {
				_ = s.store.Consume(context.WithoutCancel(ctx), input.MFAToken, claimID)
				release = false
			}
			return CompleteResult{}, err
		}
		if err := s.store.Consume(ctx, input.MFAToken, claimID); err != nil {
			s.revoke(ctx, verified.ProviderSessionReference)
			return CompleteResult{}, ErrUnavailable
		}
		release = false
		return CompleteResult{Status: StatusAuthenticated, Authentication: verified}, nil
	case auth.StatusInvalidCredentials:
		release = false
		return CompleteResult{}, s.failAttempt(ctx, input.MFAToken, claimID, ErrAuthenticationFail, challenge.ProviderSessionID)
	case auth.StatusExpired, auth.StatusLocked:
		_ = s.store.Consume(context.WithoutCancel(ctx), input.MFAToken, claimID)
		release = false
		s.revoke(ctx, challenge.ProviderSessionID)
		return CompleteResult{}, ErrAuthenticationFail
	default:
		return CompleteResult{}, ErrUnavailable
	}
}

func (s *Service) bindExisting(ctx context.Context, userID identity.UserID, challenge ChallengeData) error {
	if !validBindingSnapshot(userID, challenge) {
		return ErrAuthenticationFail
	}
	result, err := s.accounts.BindExistingWithWeChat(ctx, BindExistingInput{
		UserID: userID, TenantID: challenge.TenantID, Subject: challenge.Subject, Phone: challenge.Phone,
		NormalizedEmail: challenge.NormalizedEmail, ExpectedVersion: challenge.ExpectedVersion,
		ExpectedSecurityEpoch: challenge.ExpectedSecurityEpoch,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrIdentityConflict), errors.Is(err, identity.ErrIdentityLinkConflict):
			return ErrIdentityConflict
		case errors.Is(err, ErrPhoneConflict):
			return ErrPhoneConflict
		case errors.Is(err, ErrAccountInactive), errors.Is(err, identity.ErrUserNotFound):
			return ErrAccountInactive
		case errors.Is(err, ErrAccountChanged):
			return ErrAuthenticationFail
		default:
			return ErrUnavailable
		}
	}
	if result.UserID != userID {
		return ErrAuthenticationFail
	}
	return nil
}

func validBindingSnapshot(userID identity.UserID, challenge ChallengeData) bool {
	return userID != "" && challenge.TargetUserID == userID && challenge.NormalizedEmail != "" &&
		challenge.NormalizedEmail == strings.ToLower(strings.TrimSpace(challenge.NormalizedEmail)) &&
		challenge.ExpectedVersion > 0 && challenge.ExpectedSecurityEpoch > 0
}

func (s *Service) claimAndRate(ctx context.Context, rawToken, clientIP string, expected ChallengeKind) (string, ChallengeData, error) {
	if !validRawToken(rawToken) || strings.TrimSpace(clientIP) == "" {
		return "", ChallengeData{}, ErrInvalidInput
	}
	claimID, err := s.cfg.GenerateToken()
	if err != nil || !validRawToken(claimID) {
		return "", ChallengeData{}, ErrUnavailable
	}
	challenge, err := s.store.Claim(ctx, rawToken, claimID)
	if err != nil {
		switch {
		case errors.Is(err, ErrChallengeNotFound), errors.Is(err, ErrChallengeInvalid):
			return "", ChallengeData{}, ErrChallengeNotFound
		case errors.Is(err, ErrChallengeClaimed):
			return "", ChallengeData{}, ErrChallengeClaimed
		default:
			return "", ChallengeData{}, ErrUnavailable
		}
	}
	wantPurpose := ChallengePurpose
	if expected == ChallengeKindMFA {
		wantPurpose = MFAChallengePurpose
	}
	if challenge.Kind != expected || challenge.Purpose != wantPurpose {
		_ = s.store.Consume(context.WithoutCancel(ctx), rawToken, claimID)
		return "", ChallengeData{}, ErrChallengeNotFound
	}
	tokenHash := session.HashToken(rawToken)
	allowed, retryAfter, rateErr := s.rate.CheckMFA(ctx, clientIP, tokenHash, s.cfg.RateLimit, s.cfg.RateWindow)
	if rateErr != nil || !allowed {
		_ = s.store.Release(context.WithoutCancel(ctx), rawToken, claimID)
		if retryAfter <= 0 {
			retryAfter = s.cfg.RateWindow
		}
		return "", ChallengeData{}, &RateLimitError{RetryAfter: retryAfter}
	}
	// A login code and onboarding token are both renewable. Bind a second,
	// privacy-preserving bucket to the server-verified tenant/subject so one
	// WeChat identity cannot rotate proofs and addresses to enumerate emails.
	subjectHash := session.HashToken(challenge.TenantID + "\x00" + challenge.Subject)
	allowed, retryAfter, rateErr = s.rate.CheckMFA(ctx, "wechat-subject", subjectHash, s.cfg.RateLimit, s.cfg.RateWindow)
	if rateErr != nil || !allowed {
		_ = s.store.Release(context.WithoutCancel(ctx), rawToken, claimID)
		if retryAfter <= 0 {
			retryAfter = s.cfg.RateWindow
		}
		return "", ChallengeData{}, &RateLimitError{RetryAfter: retryAfter}
	}
	return claimID, challenge, nil
}

func (s *Service) checkCompletionRate(ctx context.Context, clientIP, clientNetwork, normalizedEmail string) error {
	if strings.TrimSpace(clientIP) == "" || normalizedEmail == "" {
		return ErrInvalidInput
	}
	if strings.TrimSpace(clientNetwork) == "" {
		clientNetwork = clientIP
	}
	digest := sha256.Sum256([]byte(normalizedEmail))
	allowed, retryAfter, err := s.completionRate.CheckRegistrationCreate(
		ctx, clientIP, clientNetwork, hex.EncodeToString(digest[:]), s.cfg.CompletionRatePolicy,
	)
	if err != nil || !allowed {
		if retryAfter <= 0 {
			retryAfter = s.cfg.CompletionRatePolicy.ClientIP.Window
		}
		return &RateLimitError{RetryAfter: retryAfter}
	}
	return nil
}

func (s *Service) checkTargetAccountRate(ctx context.Context, userID identity.UserID) error {
	if userID == "" {
		return ErrAuthenticationFail
	}
	key := session.HashToken(targetAccountRateDomain + string(userID))
	allowed, retryAfter, err := s.rate.CheckMFA(ctx, targetAccountRatePeer, key, s.cfg.TargetRateLimit, s.cfg.TargetRateWindow)
	if err != nil || !allowed {
		if retryAfter <= 0 {
			retryAfter = s.cfg.TargetRateWindow
		}
		return &RateLimitError{RetryAfter: retryAfter}
	}
	return nil
}

func (s *Service) failAttempt(ctx context.Context, rawToken, claimID string, publicErr error, providerSessionID string) error {
	_, err := s.store.IncrementAttempts(ctx, rawToken, s.cfg.MaxAttempts)
	if errors.Is(err, ErrMaxAttempts) {
		_ = s.store.Consume(context.WithoutCancel(ctx), rawToken, claimID)
		s.revoke(ctx, providerSessionID)
		return ErrMaxAttempts
	}
	if err != nil {
		_ = s.store.Consume(context.WithoutCancel(ctx), rawToken, claimID)
		s.revoke(ctx, providerSessionID)
		return ErrUnavailable
	}
	if err := s.store.Release(ctx, rawToken, claimID); err != nil {
		s.revoke(ctx, providerSessionID)
		return ErrUnavailable
	}
	return publicErr
}

func (s *Service) revoke(ctx context.Context, providerSessionID string) {
	if providerSessionID == "" || s.password == nil {
		return
	}
	revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = s.password.RevokeProviderSession(revokeCtx, providerSessionID)
}

func (s *Service) ready() bool {
	return s != nil && s.verifier != nil && s.bindings != nil && s.accounts != nil && s.password != nil && s.creator != nil && s.store != nil && s.rate != nil && s.completionRate != nil && s.cfg.OnboardingTTL > 0 && s.cfg.MFATTL > 0 && s.cfg.MaxAttempts > 0 && s.cfg.RateLimit > 0 && s.cfg.RateWindow > 0 && s.cfg.TargetRateLimit > 0 && s.cfg.TargetRateWindow > 0 && validCompletionRatePolicy(s.cfg.CompletionRatePolicy) && s.cfg.Now != nil && s.cfg.GenerateToken != nil
}

func validCompletionRatePolicy(policy registration.CreateRatePolicy) bool {
	limits := []registration.Limit{policy.ClientIP, policy.ClientNet, policy.Email, policy.ClientEmail}
	for _, limit := range limits {
		if limit.Max <= 0 || limit.Window <= 0 {
			return false
		}
	}
	return policy.IPv4NetBits > 0 && policy.IPv4NetBits <= 32 && policy.IPv6NetBits > 0 && policy.IPv6NetBits <= 128
}

func validProof(proof wechat.IdentityProof) bool {
	return strings.TrimSpace(proof.TenantID) == proof.TenantID && proof.TenantID != "" &&
		strings.TrimSpace(proof.Subject) == proof.Subject && proof.Subject != "" &&
		(proof.Phone == "" || strings.TrimSpace(proof.Phone) == proof.Phone)
}

func validRawToken(token string) bool {
	if token == "" || len(token) > maxChallengeTokenBytes || strings.TrimSpace(token) != token {
		return false
	}
	for _, r := range token {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validateCommonComplete(input CompleteInput) (string, error) {
	if !validRawToken(input.OnboardingToken) || !input.AcceptedTerms || input.Email == "" || input.Email != strings.TrimSpace(input.Email) || len(input.Email) > 254 || !utf8.ValidString(input.Password) || input.Password == "" || utf8.RuneCountInString(input.Password) > 128 {
		return "", ErrInvalidInput
	}
	address, err := mail.ParseAddress(input.Email)
	if err != nil || address.Address != input.Email {
		return "", ErrInvalidInput
	}
	for _, value := range []string{input.Username, input.DisplayName, input.RequestID} {
		if !utf8.ValidString(value) || strings.TrimSpace(value) != value {
			return "", ErrInvalidInput
		}
		for _, r := range value {
			if unicode.IsControl(r) {
				return "", ErrInvalidInput
			}
		}
	}
	if utf8.RuneCountInString(input.Username) > 64 || utf8.RuneCountInString(input.DisplayName) > 100 || len(input.RequestID) > 200 {
		return "", ErrInvalidInput
	}
	return strings.ToLower(input.Email), nil
}

func validMFAInput(input MFAInput) bool {
	if !validRawToken(input.MFAToken) || strings.TrimSpace(input.ClientIP) == "" {
		return false
	}
	switch input.Method {
	case auth.MFAMethodTOTP:
		return len(input.Code) == 6 && allDigits(input.Code) && len(input.PasskeyAssertion) == 0
	case auth.MFAMethodPasskey:
		return input.Code == "" && len(input.PasskeyAssertion) > 0 && len(input.PasskeyAssertion) <= 64<<10
	case auth.MFAMethodRecovery:
		return input.Code != "" && len(input.Code) <= 256 && len(input.PasskeyAssertion) == 0
	default:
		return false
	}
}

func allDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func methodAvailable(methods []auth.MFAMethod, target auth.MFAMethod) bool {
	for _, method := range methods {
		if method == target {
			return true
		}
	}
	return false
}

func terminalBindingError(err error) bool {
	return errors.Is(err, ErrIdentityConflict) || errors.Is(err, ErrPhoneConflict) ||
		errors.Is(err, ErrAccountInactive) || errors.Is(err, ErrAuthenticationFail)
}
