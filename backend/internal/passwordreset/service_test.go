package passwordreset

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/email"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const strongPassword = "Ving123456789."

type stubUsers struct {
	user identity.User
	err  error
	seen []string
}

func (s *stubUsers) GetByEmail(_ context.Context, address string) (identity.User, error) {
	s.seen = append(s.seen, address)
	if s.err != nil {
		return identity.User{}, s.err
	}
	return s.user, nil
}

type stubTokens struct {
	records   map[string]TokenRecord
	created   []string
	createErr error
}

func (s *stubTokens) Create(_ context.Context, rawToken string, record TokenRecord, _ time.Duration) error {
	if s.createErr != nil {
		return s.createErr
	}
	if s.records == nil {
		s.records = map[string]TokenRecord{}
	}
	s.records[rawToken] = record
	s.created = append(s.created, rawToken)
	return nil
}

func (s *stubTokens) Consume(_ context.Context, rawToken string) (TokenRecord, error) {
	record, ok := s.records[rawToken]
	if !ok {
		return TokenRecord{}, ErrInvalidToken
	}
	delete(s.records, rawToken)
	return record, nil
}

type stubPasswords struct {
	err     error
	userIDs []identity.UserID
}

func (s *stubPasswords) SetPassword(_ context.Context, userID identity.UserID, _ auth.SecretPassword) error {
	s.userIDs = append(s.userIDs, userID)
	return s.err
}

type stubSessions struct {
	revoked         int
	providerFailure string
	err             error
	userIDs         []identity.UserID
}

func (s *stubSessions) RevokeAllUserSessionsByAdmin(_ context.Context, userID identity.UserID) (int, string, error) {
	s.userIDs = append(s.userIDs, userID)
	return s.revoked, s.providerFailure, s.err
}

type stubMailer struct {
	messages []email.Message
	err      error
}

func (s *stubMailer) Send(_ context.Context, message email.Message) error {
	s.messages = append(s.messages, message)
	return s.err
}

type stubAuditor struct {
	events []session.SecurityAuditEvent
}

func (s *stubAuditor) RecordSessionEvent(_ context.Context, event session.SecurityAuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func activeUser() identity.User {
	return identity.User{
		ID:            "user_1",
		Status:        identity.UserStatusActive,
		DisplayName:   "ving",
		Email:         "ving@example.com",
		EmailVerified: true,
	}
}

func newTestService(users UserReader, tokens TokenStore, passwords PasswordSetter, sessions SessionRevoker, mailer Mailer, auditor Auditor) *Service {
	return NewService(users, tokens, passwords, sessions, mailer, auditor,
		Config{PublicOrigin: "https://auth.moonstone.org.cn", TokenTTL: 30 * time.Minute}, nil)
}

func TestRequestSendsMailForVerifiedActiveUser(t *testing.T) {
	users := &stubUsers{user: activeUser()}
	tokens := &stubTokens{}
	mailer := &stubMailer{}
	auditor := &stubAuditor{}
	service := newTestService(users, tokens, &stubPasswords{}, &stubSessions{}, mailer, auditor)

	if err := service.Request(context.Background(), RequestInput{Identifier: " Ving@Example.com "}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if len(users.seen) != 1 || users.seen[0] != "ving@example.com" {
		t.Fatalf("unexpected lookup: %v", users.seen)
	}
	if len(tokens.created) != 1 || tokens.records[tokens.created[0]].UserID != "user_1" {
		t.Fatalf("token was not stored: %v", tokens.created)
	}
	if len(mailer.messages) != 1 {
		t.Fatalf("expected one message, got %d", len(mailer.messages))
	}
	message := mailer.messages[0]
	if message.To != "ving@example.com" {
		t.Fatalf("unexpected recipient %q", message.To)
	}
	if !strings.Contains(message.HTML, "/reset-password?token=") {
		t.Fatalf("reset link missing from body: %s", message.HTML)
	}
	if !strings.Contains(message.HTML, "auth.moonstone.org.cn") {
		t.Fatalf("public origin missing from body: %s", message.HTML)
	}
	if len(auditor.events) != 1 || auditor.events[0].EventType != EventResetRequested {
		t.Fatalf("unexpected audit rows: %v", auditor.events)
	}
}

func TestRequestStaysSilentForUnknownAccount(t *testing.T) {
	users := &stubUsers{err: identity.ErrUserNotFound}
	mailer := &stubMailer{}
	service := newTestService(users, &stubTokens{}, &stubPasswords{}, &stubSessions{}, mailer, nil)

	if err := service.Request(context.Background(), RequestInput{Identifier: "missing@example.com"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if len(mailer.messages) != 0 {
		t.Fatalf("unexpected message for unknown account")
	}
	if len(users.seen) != 1 {
		t.Fatalf("lookup did not run: %v", users.seen)
	}
}

func TestRequestStaysSilentForUnverifiedAccount(t *testing.T) {
	user := activeUser()
	user.EmailVerified = false
	mailer := &stubMailer{}
	service := newTestService(&stubUsers{user: user}, &stubTokens{}, &stubPasswords{}, &stubSessions{}, mailer, nil)

	if err := service.Request(context.Background(), RequestInput{Identifier: user.Email}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if len(mailer.messages) != 0 {
		t.Fatalf("unexpected message for unverified account")
	}
}

func TestRequestStaysSilentForNonEmailIdentifier(t *testing.T) {
	users := &stubUsers{user: activeUser()}
	mailer := &stubMailer{}
	service := newTestService(users, &stubTokens{}, &stubPasswords{}, &stubSessions{}, mailer, nil)

	if err := service.Request(context.Background(), RequestInput{Identifier: "ving"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if len(users.seen) != 0 {
		t.Fatalf("account lookup must not run for a non-email identifier: %v", users.seen)
	}
	if len(mailer.messages) != 0 {
		t.Fatalf("unexpected message for a non-email identifier")
	}
}

func TestRequestSurvivesMailDeliveryFailure(t *testing.T) {
	users := &stubUsers{user: activeUser()}
	mailer := &stubMailer{err: errors.New("smtp unavailable")}
	service := newTestService(users, &stubTokens{}, &stubPasswords{}, &stubSessions{}, mailer, nil)

	if err := service.Request(context.Background(), RequestInput{Identifier: users.user.Email}); err != nil {
		t.Fatalf("delivery failure must not leak: %v", err)
	}
}

func TestConfirmRejectsWeakPassword(t *testing.T) {
	tokens := &stubTokens{records: map[string]TokenRecord{"raw": {UserID: "user_1"}}}
	passwords := &stubPasswords{}
	service := newTestService(&stubUsers{}, tokens, passwords, &stubSessions{}, &stubMailer{}, nil)

	if _, err := service.Confirm(context.Background(), ConfirmInput{Token: "raw", NewPassword: "short"}); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("expected weak password rejection, got %v", err)
	}
	if len(passwords.userIDs) != 0 {
		t.Fatalf("provider must not be called for a weak password")
	}
	if _, ok := tokens.records["raw"]; !ok {
		t.Fatalf("token must survive a pre-validation failure")
	}
}

func TestConfirmRejectsUnknownToken(t *testing.T) {
	passwords := &stubPasswords{}
	service := newTestService(&stubUsers{}, &stubTokens{}, passwords, &stubSessions{}, &stubMailer{}, nil)

	if _, err := service.Confirm(context.Background(), ConfirmInput{Token: "unknown", NewPassword: strongPassword}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected invalid token, got %v", err)
	}
	if len(passwords.userIDs) != 0 {
		t.Fatalf("provider must not be called for an unknown token")
	}
}

func TestConfirmSetsPasswordAndRevokesSessions(t *testing.T) {
	tokens := &stubTokens{records: map[string]TokenRecord{"raw": {UserID: "user_1"}}}
	passwords := &stubPasswords{}
	sessions := &stubSessions{revoked: 2}
	auditor := &stubAuditor{}
	service := newTestService(&stubUsers{}, tokens, passwords, sessions, &stubMailer{}, auditor)

	result, err := service.Confirm(context.Background(), ConfirmInput{Token: "raw", NewPassword: strongPassword})
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if result.UserID != "user_1" || result.RevokedSessions != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(passwords.userIDs) != 1 || passwords.userIDs[0] != "user_1" {
		t.Fatalf("provider not called: %v", passwords.userIDs)
	}
	if len(sessions.userIDs) != 1 {
		t.Fatalf("sessions not revoked: %v", sessions.userIDs)
	}
	if _, ok := tokens.records["raw"]; ok {
		t.Fatalf("token must be consumed exactly once")
	}
	if len(auditor.events) != 1 || auditor.events[0].EventType != EventResetCompleted {
		t.Fatalf("unexpected audit rows: %v", auditor.events)
	}
}

func TestConfirmReportsProviderFailure(t *testing.T) {
	tokens := &stubTokens{records: map[string]TokenRecord{"raw": {UserID: "user_1"}}}
	passwords := &stubPasswords{err: auth.ErrPasswordChangeFailed}
	sessions := &stubSessions{revoked: 1}
	service := newTestService(&stubUsers{}, tokens, passwords, sessions, &stubMailer{}, nil)

	if _, err := service.Confirm(context.Background(), ConfirmInput{Token: "raw", NewPassword: strongPassword}); !errors.Is(err, ErrPasswordChangeFailed) {
		t.Fatalf("expected provider failure, got %v", err)
	}
	if len(sessions.userIDs) != 0 {
		t.Fatalf("sessions must not be revoked after a failed provider call")
	}
}

func TestConfirmClassifiesUnknownProviderOutcome(t *testing.T) {
	tokens := &stubTokens{records: map[string]TokenRecord{"raw": {UserID: "user_1"}}}
	passwords := &stubPasswords{err: auth.ErrPasswordChangeUnknown}
	service := newTestService(&stubUsers{}, tokens, passwords, &stubSessions{}, &stubMailer{}, nil)

	if _, err := service.Confirm(context.Background(), ConfirmInput{Token: "raw", NewPassword: strongPassword}); !errors.Is(err, ErrPasswordChangeUnknown) {
		t.Fatalf("expected unknown outcome, got %v", err)
	}
}

func TestValidatePasswordRules(t *testing.T) {
	cases := []struct {
		password string
		wantErr  bool
	}{
		{password: strongPassword},
		{password: "Ving12345678", wantErr: true},
		{password: "ving123456789.", wantErr: true},
		{password: "VING123456789.", wantErr: true},
		{password: "Vingabcdefghij.", wantErr: true},
		{password: "", wantErr: true},
	}
	for _, testCase := range cases {
		err := ValidatePassword(testCase.password)
		if testCase.wantErr && !errors.Is(err, ErrWeakPassword) {
			t.Fatalf("expected weak password for %q, got %v", testCase.password, err)
		}
		if !testCase.wantErr && err != nil {
			t.Fatalf("expected acceptance for %q, got %v", testCase.password, err)
		}
	}
}

func TestRequestUnavailableWithoutDependencies(t *testing.T) {
	service := newTestService(nil, nil, nil, nil, nil, nil)
	if err := service.Request(context.Background(), RequestInput{Identifier: "ving@example.com"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
}
