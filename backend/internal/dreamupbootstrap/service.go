//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Idempotent, fail-closed DreamUP OAuth client bootstrap
//

// Package dreamupbootstrap owns the one-time DreamUP application/client
// bootstrap use case. It composes the existing applications service and a
// provider read-back port; it does not call ZITADEL internals or mutate drift.
package dreamupbootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

const (
	ApplicationName        = "MoonStone DreamUP"
	ApplicationDescription = "MoonStone DreamUP 2026 上海站"
	ClientName             = "DreamUP Web"
	RedirectURI            = "https://moonstone.org.cn/moonstone-dreamup/auth/callback"
	LogoutURI              = "https://moonstone.org.cn/moonstone-dreamup/"
	AllowedOrigin          = "https://moonstone.org.cn"
	defaultProviderName    = "zitadel"
	// BootstrapRequestPrefix contains characters rejected by the public HTTP
	// request-ID boundary. Only this offline command can mint the immutable
	// audit anchor used for authoritative future discovery.
	BootstrapRequestPrefix = "dreamup.bootstrap/"
)

var (
	errOwnerUserIDRequired  = errors.New("dreamup bootstrap: owner user id required")
	errSecretOutputRequired = errors.New("dreamup bootstrap: absolute secret output required")
	errSecretOutputFailed   = errors.New("dreamup bootstrap: secret output unavailable")
	errProvisioningFailed   = errors.New("dreamup bootstrap: provisioning failed")
	errVerificationFailed   = errors.New("dreamup bootstrap: verification failed")
	requestIDEntropy        = rand.Reader
)

// ApplicationManager is the exact applications.Service surface this command
// consumes. Creation remains in the existing domain service, preserving its
// owner lookup, PostgreSQL transaction, provider operation and audit rules.
type ApplicationManager interface {
	CreateWithInitialClient(
		ctx context.Context,
		actor identity.UserID,
		requestID string,
		appInput applications.ApplicationInput,
		clientInput applications.ClientInput,
	) (applications.CreateResult, error)
}

// ProviderExpectations are runtime topology values that must match the
// provider read-back exactly. They contain no credential material.
type ProviderExpectations struct {
	ProviderName       string
	ProjectID          string
	InteractionBaseURI string
}

// Options are operator inputs. SecretOutput is required only for first
// creation and must be an absolute path that does not already exist.
type Options struct {
	OwnerUserID  identity.UserID
	SecretOutput string
}

// Result contains stable identifiers and non-secret verification state only.
type Result struct {
	Status                string
	ApplicationID         applications.ApplicationID
	ClientID              applications.OAuthClientID
	ProviderApplicationID string
	ProviderClientID      string
	SecretProvisioned     bool
}

// DriftError identifies only the safe field class that drifted. Expected and
// observed values are intentionally omitted from output and errors.
type DriftError struct{ Field string }

func (e *DriftError) Error() string { return "dreamup bootstrap drift: " + e.Field }

// Service verifies or creates the single DreamUP application/client pair.
type Service struct {
	applications ApplicationManager
	local        applications.ProvisioningStateReader
	provider     applications.OAuthClientReadback
	expected     ProviderExpectations
	credentials  credentialSecurityPolicy
}

func NewService(
	manager ApplicationManager,
	local applications.ProvisioningStateReader,
	provider applications.OAuthClientReadback,
	expected ProviderExpectations,
) *Service {
	if expected.ProviderName == "" {
		expected.ProviderName = defaultProviderName
	}
	return &Service{
		applications: manager,
		local:        local,
		provider:     provider,
		expected:     expected,
		credentials:  newCredentialSecurityPolicy(),
	}
}

// Execute is the command-facing boundary. It never writes underlying error
// text, so a dependency that accidentally embeds a secret cannot leak it to
// stdout/stderr. Output is deliberately machine-readable and non-secret.
func (s *Service) Execute(ctx context.Context, opts Options, stdout, stderr io.Writer) int {
	result, err := s.Bootstrap(ctx, opts)
	if err != nil {
		var drift *DriftError
		if errors.As(err, &drift) {
			_, _ = fmt.Fprintf(stderr, "status=drift drift=%s\n", drift.Field)
			return 1
		}
		_, _ = fmt.Fprintf(stderr, "status=failed error=%s\n", safeErrorClass(err))
		return 1
	}
	_, _ = fmt.Fprintf(stdout,
		"status=%s application_id=%s client_id=%s provider_application_id=%s provider_client_id=%s drift=none secret_provisioned=%t\n",
		result.Status, result.ApplicationID, result.ClientID,
		result.ProviderApplicationID, result.ProviderClientID,
		result.SecretProvisioned,
	)
	return 0
}

// Bootstrap creates the DreamUP pair only when the exact application is
// absent. Existing state is read back locally and at the provider and is
// either verified with zero writes or rejected as drift.
func (s *Service) Bootstrap(ctx context.Context, opts Options) (Result, error) {
	if strings.TrimSpace(string(opts.OwnerUserID)) == "" {
		return Result{}, errOwnerUserIDRequired
	}
	if s.applications == nil || s.local == nil || s.provider == nil || s.expected.ProjectID == "" || s.expected.InteractionBaseURI == "" {
		return Result{}, errVerificationFailed
	}

	existing, found, err := s.findExisting(ctx)
	if err != nil {
		return Result{}, err
	}
	if found {
		return s.verify(ctx, existing, opts.OwnerUserID, "verified")
	}

	if opts.SecretOutput == "" || !filepath.IsAbs(opts.SecretOutput) {
		return Result{}, errSecretOutputRequired
	}
	credential, err := reserveCredentialFile(opts.SecretOutput, s.credentials)
	if err != nil {
		return Result{}, errSecretOutputFailed
	}
	defer credential.abort()

	appInput, clientInput := desiredInputs(opts.OwnerUserID)
	if err := applications.ValidateApplicationInput(appInput); err != nil {
		return Result{}, errVerificationFailed
	}
	if err := applications.ValidateClientInput(clientInput); err != nil {
		return Result{}, errVerificationFailed
	}

	requestID, err := newRequestID()
	if err != nil {
		return Result{}, errVerificationFailed
	}
	created, err := s.applications.CreateWithInitialClient(
		ctx, opts.OwnerUserID, requestID, appInput, clientInput,
	)
	if err != nil {
		return Result{}, errProvisioningFailed
	}
	if created.ClientSecret == "" {
		return Result{}, errProvisioningFailed
	}
	// Persist the provider's one-time secret before any fallible read-back.
	// Creation is already committed at this point; discarding the secret on a
	// transient verification failure would make the client unrecoverable
	// without rotation. A later verification failure therefore leaves this
	// owner-only file quarantined for the operator, never printed.
	if err := credential.store(created.ClientSecret); err != nil {
		return Result{}, errSecretOutputFailed
	}

	detail, found, err := s.findExisting(ctx)
	if err != nil {
		return Result{}, errVerificationFailed
	}
	if !found {
		return Result{}, errVerificationFailed
	}
	if detail.Application.ID != created.ApplicationID || len(detail.Clients) != 1 || detail.Clients[0].ID != created.ClientID {
		return Result{}, &DriftError{Field: "creation_mapping"}
	}
	verified, err := s.verify(ctx, detail, opts.OwnerUserID, "created")
	if err != nil {
		return Result{}, err
	}
	return verified, nil
}

func (s *Service) findExisting(ctx context.Context) (applications.ProvisioningState, bool, error) {
	states, err := s.local.FindProvisioningCandidates(ctx, applications.ProvisioningFingerprint{
		ApplicationName:        ApplicationName,
		ApplicationDescription: ApplicationDescription,
		ClientName:             ClientName,
		RedirectURI:            RedirectURI,
		LogoutURI:              LogoutURI,
		BootstrapRequestPrefix: BootstrapRequestPrefix,
	})
	if err != nil {
		return applications.ProvisioningState{}, false, err
	}
	if len(states) == 0 {
		return applications.ProvisioningState{}, false, nil
	}
	anchored := make([]applications.ProvisioningState, 0, len(states))
	for _, state := range states {
		if state.BootstrapAnchored {
			anchored = append(anchored, state)
		}
	}
	if len(anchored) != 0 {
		states = anchored
	}
	if len(states) != 1 {
		return applications.ProvisioningState{}, false, &DriftError{Field: "application_count"}
	}
	return states[0], true, nil
}

func desiredInputs(owner identity.UserID) (applications.ApplicationInput, applications.ClientInput) {
	tokenAuth := applications.TokenAuthClientSecretBasic
	return applications.ApplicationInput{
			Name:        ApplicationName,
			Description: ApplicationDescription,
			Audience:    applications.AudienceExternal,
			OwnerID:     string(owner),
		}, applications.ClientInput{
			Name:         ClientName,
			Profile:      applications.ClientProfileWebServer,
			RedirectURIs: []string{RedirectURI},
			LogoutURI:    LogoutURI,
			Scopes:       []string{"openid", "profile", "email"},
			ConsentMode:  applications.ConsentModeFirstAuthorization,
			GrantTypes: []applications.OAuthGrantType{
				applications.GrantTypeAuthorizationCode,
				applications.GrantTypeRefreshToken,
			},
			TokenEndpointAuth: &tokenAuth,
		}
}

func (s *Service) verify(ctx context.Context, detail applications.ProvisioningState, owner identity.UserID, status string) (Result, error) {
	app := detail.Application
	switch {
	case app.Name != ApplicationName:
		return Result{}, &DriftError{Field: "application_name"}
	case app.Description != ApplicationDescription:
		return Result{}, &DriftError{Field: "application_description"}
	case app.Audience != applications.AudienceExternal:
		return Result{}, &DriftError{Field: "application_audience"}
	case app.OwnerID != owner:
		return Result{}, &DriftError{Field: "application_owner"}
	case app.Status != applications.StatusActive:
		return Result{}, &DriftError{Field: "application_status"}
	case app.Provisioning != applications.ProvisioningStatusProvisioned:
		return Result{}, &DriftError{Field: "application_provisioning"}
	case app.DeletedAt != nil:
		return Result{}, &DriftError{Field: "application_deleted"}
	case len(detail.Clients) != 1:
		return Result{}, &DriftError{Field: "client_count"}
	}

	client := detail.Clients[0]
	switch {
	case client.ApplicationID != app.ID:
		return Result{}, &DriftError{Field: "client_application"}
	case client.Name != ClientName:
		return Result{}, &DriftError{Field: "client_name"}
	case client.Profile != applications.ClientProfileWebServer:
		return Result{}, &DriftError{Field: "profile"}
	case client.ClientType != applications.ClientTypeConfidential:
		return Result{}, &DriftError{Field: "client_type"}
	case client.TokenEndpointAuth != applications.TokenAuthClientSecretBasic:
		return Result{}, &DriftError{Field: "token_endpoint_auth"}
	case client.ConsentMode != applications.ConsentModeFirstAuthorization:
		return Result{}, &DriftError{Field: "consent_mode"}
	case client.Status != applications.StatusActive:
		return Result{}, &DriftError{Field: "client_status"}
	case client.Provisioning != applications.ProvisioningStatusProvisioned:
		return Result{}, &DriftError{Field: "client_provisioning"}
	case client.DeletedAt != nil:
		return Result{}, &DriftError{Field: "client_deleted"}
	case client.ProviderReconciliationRequired:
		return Result{}, &DriftError{Field: "client_provider_reconciliation"}
	case client.SecretRotationStatus != applications.SecretRotationIdle:
		return Result{}, &DriftError{Field: "client_secret_rotation"}
	case len(client.RedirectURIs) != 1 || client.RedirectURIs[0].URI != RedirectURI:
		return Result{}, &DriftError{Field: "redirect_uri"}
	case client.LogoutURI != LogoutURI:
		return Result{}, &DriftError{Field: "logout_uri"}
	case !sameStrings(client.Scopes, []string{"openid", "profile", "email"}):
		return Result{}, &DriftError{Field: "scopes"}
	case client.Provider != s.expected.ProviderName:
		return Result{}, &DriftError{Field: "provider"}
	case client.ProviderProjectID != s.expected.ProjectID:
		return Result{}, &DriftError{Field: "provider_project"}
	case client.ProviderApplicationID == "" || client.ProviderClientID == "":
		return Result{}, &DriftError{Field: "provider_mapping"}
	case len(client.SecretRecords) == 0:
		return Result{}, &DriftError{Field: "secret_provisioning"}
	}

	snapshot, err := s.provider.ReadClient(ctx, client.ProviderApplicationID)
	if err != nil {
		return Result{}, &DriftError{Field: "provider_readback"}
	}
	wantDisplay := applications.ProviderDisplayName(ApplicationName, ClientName, client.ID)
	switch {
	case snapshot.ProviderProjectID != s.expected.ProjectID:
		return Result{}, &DriftError{Field: "provider_project"}
	case snapshot.ProviderApplicationID != client.ProviderApplicationID || snapshot.ProviderClientID != client.ProviderClientID:
		return Result{}, &DriftError{Field: "provider_mapping"}
	case snapshot.DisplayName != wantDisplay:
		return Result{}, &DriftError{Field: "provider_display_name"}
	case snapshot.Profile != applications.ClientProfileWebServer:
		return Result{}, &DriftError{Field: "provider_profile"}
	case snapshot.TokenEndpointAuth != applications.TokenAuthClientSecretBasic:
		return Result{}, &DriftError{Field: "provider_token_endpoint_auth"}
	case !snapshot.Active:
		return Result{}, &DriftError{Field: "provider_status"}
	case !sameStrings(snapshot.RedirectURIs, []string{RedirectURI}):
		return Result{}, &DriftError{Field: "provider_redirect_uri"}
	case !sameStrings(snapshot.LogoutURIs, []string{LogoutURI}):
		return Result{}, &DriftError{Field: "provider_logout_uri"}
	case !sameResponseTypes(snapshot.ResponseTypes, []applications.OAuthResponseType{applications.ResponseTypeCode}):
		return Result{}, &DriftError{Field: "provider_response_types"}
	case !sameGrantTypes(snapshot.GrantTypes, []applications.OAuthGrantType{
		applications.GrantTypeAuthorizationCode,
		applications.GrantTypeRefreshToken,
	}):
		return Result{}, &DriftError{Field: "provider_grant_types"}
	case snapshot.LoginVersionBaseURI != s.expected.InteractionBaseURI:
		return Result{}, &DriftError{Field: "provider_login_version"}
	case snapshot.DevMode:
		return Result{}, &DriftError{Field: "provider_dev_mode"}
	case snapshot.OIDCVersion != applications.OIDCVersion10:
		return Result{}, &DriftError{Field: "provider_oidc_version"}
	case snapshot.AccessTokenType != applications.AccessTokenTypeBearer:
		return Result{}, &DriftError{Field: "provider_access_token_type"}
	case snapshot.NonCompliant:
		return Result{}, &DriftError{Field: "provider_compliance"}
	case snapshot.AccessTokenRoleAssertion:
		return Result{}, &DriftError{Field: "provider_access_token_role_assertion"}
	case snapshot.IDTokenRoleAssertion:
		return Result{}, &DriftError{Field: "provider_id_token_role_assertion"}
	case snapshot.IDTokenUserinfoAssertion:
		return Result{}, &DriftError{Field: "provider_id_token_userinfo_assertion"}
	case snapshot.ClockSkewNanoseconds != 0:
		return Result{}, &DriftError{Field: "provider_clock_skew"}
	case len(snapshot.AdditionalOrigins) != 0:
		return Result{}, &DriftError{Field: "provider_additional_origins"}
	case snapshot.SkipNativeAppSuccessPage:
		return Result{}, &DriftError{Field: "provider_native_success_page"}
	case snapshot.BackChannelLogoutURI != "":
		return Result{}, &DriftError{Field: "provider_backchannel_logout"}
	case !sameStrings(snapshot.AllowedOrigins, []string{AllowedOrigin}):
		return Result{}, &DriftError{Field: "provider_allowed_origins"}
	}

	return Result{
		Status:                status,
		ApplicationID:         app.ID,
		ClientID:              client.ID,
		ProviderApplicationID: client.ProviderApplicationID,
		ProviderClientID:      client.ProviderClientID,
		SecretProvisioned:     true,
	}, nil
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	counts := make(map[string]int, len(want))
	for _, value := range want {
		counts[value]++
	}
	for _, value := range got {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

func sameResponseTypes(got, want []applications.OAuthResponseType) bool {
	gotStrings := make([]string, len(got))
	wantStrings := make([]string, len(want))
	for i := range got {
		gotStrings[i] = string(got[i])
	}
	for i := range want {
		wantStrings[i] = string(want[i])
	}
	return sameStrings(gotStrings, wantStrings)
}

func sameGrantTypes(got, want []applications.OAuthGrantType) bool {
	gotStrings := make([]string, len(got))
	wantStrings := make([]string, len(want))
	for i := range got {
		gotStrings[i] = string(got[i])
	}
	for i := range want {
		wantStrings[i] = string(want[i])
	}
	return sameStrings(gotStrings, wantStrings)
}

func safeErrorClass(err error) string {
	switch {
	case errors.Is(err, errOwnerUserIDRequired):
		return "owner_user_id_required"
	case errors.Is(err, errSecretOutputRequired):
		return "secret_output_required"
	case errors.Is(err, errSecretOutputFailed):
		return "secret_output_unavailable"
	case errors.Is(err, errProvisioningFailed):
		return "provisioning_failed"
	default:
		return "verification_failed"
	}
}

func newRequestID() (string, error) {
	raw := make([]byte, 12)
	if _, err := io.ReadFull(requestIDEntropy, raw); err != nil {
		return "", err
	}
	return BootstrapRequestPrefix + hex.EncodeToString(raw), nil
}

type credentialFile struct {
	path      string
	file      *os.File
	committed bool
}

type credentialSecurityPolicy interface {
	validateParent(string) error
	secureAndValidate(*os.File) error
}

func reserveCredentialFile(path string, policy credentialSecurityPolicy) (*credentialFile, error) {
	if policy == nil {
		return nil, errSecretOutputFailed
	}
	parentPath := filepath.Dir(path)
	parent, err := os.Lstat(parentPath)
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return nil, errSecretOutputFailed
	}
	if err := policy.validateParent(parentPath); err != nil {
		return nil, errSecretOutputFailed
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, errSecretOutputFailed
	}
	credential := &credentialFile{path: path, file: file}
	if err := policy.secureAndValidate(file); err != nil {
		credential.abort()
		return nil, errSecretOutputFailed
	}
	return credential, nil
}

func (c *credentialFile) store(secret string) error {
	if c == nil || c.file == nil || secret == "" {
		return errSecretOutputFailed
	}
	if _, err := io.WriteString(c.file, secret); err != nil {
		return errSecretOutputFailed
	}
	if err := c.file.Sync(); err != nil {
		return errSecretOutputFailed
	}
	if err := c.file.Close(); err != nil {
		c.file = nil
		return errSecretOutputFailed
	}
	c.file = nil
	c.committed = true
	return nil
}

func (c *credentialFile) abort() {
	if c == nil || c.committed {
		return
	}
	if c.file != nil {
		_ = c.file.Close()
		c.file = nil
	}
	_ = os.Remove(c.path)
}
