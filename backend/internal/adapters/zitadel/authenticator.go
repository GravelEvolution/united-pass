// Package zitadel implements the authentication provider adapter for ZITADEL
// using the LoginV2 API (zitadel.session.v2) and the user API
// (zitadel.user.v2). It satisfies the auth.Authenticator and
// httpapi.ReadinessChecker interfaces.
//
// Authentication flow:
//
//	BeginPasswordAuthentication: CreateSession (user + password checks),
//	  then detect second factors via the response challenges and
//	  ListAuthenticationMethodTypes (TOTP).
//	CompleteMFA: SetSession with a TOTP or WebAuthN check.
//	RevokeProviderSession: DeleteSession.
//
// The adapter talks to ZITADEL as a service account (JWT profile
// authentication) so no end-user token ever reaches the ZITADEL API on behalf
// of our service; end-user sessions are only referenced by their opaque IDs
// and tokens inside MFA tokens and provider session references.
package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"

	sessionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

// ProviderName is the value of UP_AUTH_PROVIDER that selects this adapter.
const ProviderName = "zitadel"

// sessionService is the subset of the ZITADEL session service the adapter
// uses. It is an interface so tests can substitute a fake.
type sessionService interface {
	CreateSession(ctx context.Context, in *sessionv2.CreateSessionRequest, opts ...grpc.CallOption) (*sessionv2.CreateSessionResponse, error)
	SetSession(ctx context.Context, in *sessionv2.SetSessionRequest, opts ...grpc.CallOption) (*sessionv2.SetSessionResponse, error)
	GetSession(ctx context.Context, in *sessionv2.GetSessionRequest, opts ...grpc.CallOption) (*sessionv2.GetSessionResponse, error)
	ListSessions(ctx context.Context, in *sessionv2.ListSessionsRequest, opts ...grpc.CallOption) (*sessionv2.ListSessionsResponse, error)
	DeleteSession(ctx context.Context, in *sessionv2.DeleteSessionRequest, opts ...grpc.CallOption) (*sessionv2.DeleteSessionResponse, error)
}

// userService is the subset of the ZITADEL user service the adapter uses.
type userService interface {
	ListAuthenticationMethodTypes(ctx context.Context, in *userv2.ListAuthenticationMethodTypesRequest, opts ...grpc.CallOption) (*userv2.ListAuthenticationMethodTypesResponse, error)
}

// Authenticator implements auth.Authenticator against ZITADEL's LoginV2 API.
type Authenticator struct {
	sessions sessionService
	users    userService
	linker   identity.UserLinker

	provider string // always ProviderName; used as the identity_links provider
	tenantID string // organization/instance scope for identity links
	domain   string // WebAuthn relying-party domain for passkey challenges
	logger   *slog.Logger
}

// NewAuthenticator builds the ZITADEL authenticator from a pre-constructed
// session and user service, the local identity linker, and configuration
// values. domain must be the WebAuthn relying-party domain (e.g. the API host)
// used when requesting passkey challenges; it may be empty to disable passkey
// MFA challenges.
func NewAuthenticator(
	sessions sessionService,
	users userService,
	linker identity.UserLinker,
	tenantID string,
	domain string,
	logger *slog.Logger,
) *Authenticator {
	return &Authenticator{
		sessions: sessions,
		users:    users,
		linker:   linker,
		provider: ProviderName,
		tenantID: tenantID,
		domain:   domain,
		logger:   logger,
	}
}

// BeginPasswordAuthentication creates a ZITADEL session with user + password
// checks and determines whether a second factor is required.
//
// Status mapping:
//   - password/user check failed   -> StatusInvalidCredentials (generic)
//   - provider unreachable         -> StatusProviderUnavailable
//   - response carries challenges  -> StatusMFARequired (passkey)
//   - user has TOTP registered     -> StatusMFARequired (totp)
//   - otherwise                    -> StatusAuthenticated
//
// The returned MFAToken and ProviderSessionReference both encode
// "{sessionID}:{sessionToken}" — an opaque handle to the ZITADEL session.
func (a *Authenticator) BeginPasswordAuthentication(
	ctx context.Context,
	input auth.PasswordAuthenticationInput,
) (auth.AuthenticationResult, error) {
	create, err := a.sessions.CreateSession(ctx, &sessionv2.CreateSessionRequest{
		Checks: &sessionv2.Checks{
			User: &sessionv2.CheckUser{
				Search: &sessionv2.CheckUser_LoginName{LoginName: input.Identifier},
			},
			Password: &sessionv2.CheckPassword{Password: input.Password},
		},
		Challenges: a.requestChallenges(),
	})
	if err != nil {
		if status := mapAuthError(err); status != auth.StatusInvalidCredentials {
			return auth.AuthenticationResult{Status: status}, nil
		}
		return auth.AuthenticationResult{Status: auth.StatusInvalidCredentials}, nil
	}

	mfaToken := encodeSessionRef(create.SessionId, create.SessionToken)

	// Passkey challenge requested and granted by ZITADEL.
	if create.Challenges != nil && create.Challenges.WebAuthN != nil {
		return auth.AuthenticationResult{
			Status:           auth.StatusMFARequired,
			MFAToken:         mfaToken,
			AvailableMethods: []auth.MFAMethod{auth.MFAMethodPasskey},
		}, nil
	}

	// No challenge: check whether the user registered TOTP.
	userID, err := a.sessionUserID(ctx, create.SessionId)
	if err != nil {
		return auth.AuthenticationResult{}, err
	}
	hasTOTP, err := a.userHasTOTP(ctx, userID)
	if err != nil {
		return auth.AuthenticationResult{}, err
	}
	if hasTOTP {
		return auth.AuthenticationResult{
			Status:           auth.StatusMFARequired,
			MFAToken:         mfaToken,
			AvailableMethods: []auth.MFAMethod{auth.MFAMethodTOTP},
		}, nil
	}

	return a.resolveAuthenticated(ctx, create.SessionId, create.SessionToken, userID,
		[]auth.AuthenticationMethod{auth.MethodPassword})
}

// CompleteMFA completes a second-factor check against the ZITADEL session
// referenced by the MFA token.
func (a *Authenticator) CompleteMFA(
	ctx context.Context,
	input auth.MFAChallengeInput,
) (auth.AuthenticationResult, error) {
	sessionID, sessionToken, err := decodeSessionRef(input.MFAToken)
	if err != nil {
		return auth.AuthenticationResult{Status: auth.StatusExpired}, nil
	}

	req := &sessionv2.SetSessionRequest{
		SessionId:    sessionID,
		SessionToken: sessionToken,
	}
	switch input.Method {
	case auth.MFAMethodTOTP:
		req.Checks = &sessionv2.Checks{
			Totp: &sessionv2.CheckTOTP{Code: input.Code},
		}
	case auth.MFAMethodPasskey:
		// The WebAuthn assertion arrives as JSON; convert it to a protobuf
		// Struct as required by CheckWebAuthN.CredentialAssertionData.
		assertion, err := structFromJSON(input.PasskeyAssertion)
		if err != nil {
			return auth.AuthenticationResult{Status: auth.StatusInvalidCredentials}, nil
		}
		req.Checks = &sessionv2.Checks{
			WebAuthN: &sessionv2.CheckWebAuthN{CredentialAssertionData: assertion},
		}
	default:
		// Recovery codes are not implemented for ZITADEL in Phase 1.2.
		return auth.AuthenticationResult{Status: auth.StatusInvalidCredentials}, nil
	}

	set, err := a.sessions.SetSession(ctx, req)
	if err != nil {
		if status := mapAuthError(err); status != auth.StatusInvalidCredentials {
			return auth.AuthenticationResult{Status: status}, nil
		}
		return auth.AuthenticationResult{Status: auth.StatusInvalidCredentials}, nil
	}

	userID, err := a.sessionUserID(ctx, sessionID)
	if err != nil {
		return auth.AuthenticationResult{}, err
	}
	methods := []auth.AuthenticationMethod{auth.MethodPassword}
	switch input.Method {
	case auth.MFAMethodTOTP:
		methods = append(methods, auth.MethodTOTP)
	case auth.MFAMethodPasskey:
		methods = append(methods, auth.MethodPasskey)
	}
	return a.resolveAuthenticated(ctx, sessionID, set.SessionToken, userID, methods)
}

// RevokeProviderSession terminates the ZITADEL session referenced by the
// provider session reference. It is best-effort: the local session is already
// deleted by the caller.
func (a *Authenticator) RevokeProviderSession(
	ctx context.Context,
	sessionReference string,
) error {
	sessionID, _, err := decodeSessionRef(sessionReference)
	if err != nil {
		return fmt.Errorf("zitadel: invalid session reference: %w", err)
	}
	_, err = a.sessions.DeleteSession(ctx, &sessionv2.DeleteSessionRequest{
		SessionId: sessionID,
	})
	if err != nil {
		return fmt.Errorf("zitadel: revoke session: %w", err)
	}
	return nil
}

// Check reports ZITADEL API connectivity for readiness checks. It lists
// sessions (empty query) which fails when the service account cannot reach or
// authenticate against the ZITADEL API.
func (a *Authenticator) Check(ctx context.Context) error {
	_, err := a.sessions.ListSessions(ctx, &sessionv2.ListSessionsRequest{})
	if err != nil {
		return fmt.Errorf("zitadel: %w", err)
	}
	return nil
}

// Name implements httpapi.ReadinessChecker.
func (a *Authenticator) Name() string { return "auth_provider" }

// requestChallenges builds the passkey challenge request. TOTP needs no
// challenge (SetSession with a TOTP check works directly); email/SMS OTP are
// not requested because they require delivery infrastructure.
func (a *Authenticator) requestChallenges() *sessionv2.RequestChallenges {
	if a.domain == "" {
		return nil
	}
	return &sessionv2.RequestChallenges{
		WebAuthN: &sessionv2.RequestChallenges_WebAuthN{
			Domain:                      a.domain,
			UserVerificationRequirement: sessionv2.UserVerificationRequirement_USER_VERIFICATION_REQUIREMENT_REQUIRED,
		},
	}
}

// sessionUserID resolves the verified user ID of a ZITADEL session.
func (a *Authenticator) sessionUserID(ctx context.Context, sessionID string) (string, error) {
	resp, err := a.sessions.GetSession(ctx, &sessionv2.GetSessionRequest{
		SessionId: sessionID,
	})
	if err != nil {
		return "", fmt.Errorf("zitadel: get session: %w", err)
	}
	if resp.Session == nil || resp.Session.Factors == nil || resp.Session.Factors.User == nil {
		return "", errors.New("zitadel: session has no verified user factor")
	}
	return resp.Session.Factors.User.Id, nil
}

// userHasTOTP reports whether the user registered a TOTP authenticator.
func (a *Authenticator) userHasTOTP(ctx context.Context, userID string) (bool, error) {
	resp, err := a.users.ListAuthenticationMethodTypes(ctx, &userv2.ListAuthenticationMethodTypesRequest{
		UserId: userID,
	})
	if err != nil {
		return false, fmt.Errorf("zitadel: list authentication methods: %w", err)
	}
	for _, m := range resp.AuthMethodTypes {
		if m == userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_TOTP {
			return true, nil
		}
	}
	return false, nil
}

// resolveAuthenticated maps the ZITADEL session to the local United Pass
// user (creating it on first login) and returns an authenticated result.
func (a *Authenticator) resolveAuthenticated(
	ctx context.Context,
	sessionID, sessionToken, providerUserID string,
	methods []auth.AuthenticationMethod,
) (auth.AuthenticationResult, error) {
	user, err := a.linker.GetOrCreateUserByProviderSubject(ctx, a.provider, a.tenantID, identity.ProviderUserInfo{
		Subject: providerUserID,
	})
	if err != nil {
		return auth.AuthenticationResult{}, fmt.Errorf("zitadel: resolve local user: %w", err)
	}
	if !user.Status.CanAuthenticate() {
		return auth.AuthenticationResult{Status: auth.StatusLocked}, nil
	}

	return auth.AuthenticationResult{
		Status:                   auth.StatusAuthenticated,
		UserID:                   user.ID,
		Provider:                 a.provider,
		ProviderSessionReference: encodeSessionRef(sessionID, sessionToken),
		AuthenticationMethods:    methods,
	}, nil
}

// encodeSessionRef packs a ZITADEL session ID and token into a single opaque
// string. The token is a random opaque value from ZITADEL and is stored
// encrypted at rest by the session service.
func encodeSessionRef(sessionID, sessionToken string) string {
	return sessionID + ":" + sessionToken
}

// decodeSessionRef splits an encoded session reference into its parts. It
// returns an error when the format is invalid, which callers map to expired
// credentials (the session handle is unusable).
func decodeSessionRef(ref string) (sessionID, sessionToken string, err error) {
	sessionID, sessionToken, ok := strings.Cut(ref, ":")
	if !ok || sessionID == "" || sessionToken == "" {
		return "", "", errors.New("invalid session reference")
	}
	return sessionID, sessionToken, nil
}

// structFromJSON converts a JSON-encoded WebAuthn assertion into the protobuf
// Struct expected by CheckWebAuthN.
func structFromJSON(raw string) (*structpb.Struct, error) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("zitadel: parse webauthn assertion: %w", err)
	}
	s, err := structpb.NewStruct(m)
	if err != nil {
		return nil, fmt.Errorf("zitadel: build webauthn assertion struct: %w", err)
	}
	return s, nil
}
