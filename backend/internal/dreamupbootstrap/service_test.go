//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: DreamUP OAuth client bootstrap contract tests
//

package dreamupbootstrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

const (
	testOwnerID       = identity.UserID("usr_dreamup_owner")
	testApplicationID = applications.ApplicationID("app_dreamup")
	testClientID      = applications.OAuthClientID("clt_dreamup")
	testProviderAppID = "provider-app-dreamup"
	testProviderID    = "provider-client-dreamup"
	testProjectID     = "provider-project"
	testSecret        = "one-time-dreamup-client-secret-never-print"
	testInteraction   = "https://pass.moonstone.org.cn/_interaction"
)

type fakeApplicationManager struct {
	found       bool
	duplicate   bool
	detail      applications.Detail
	createErr   error
	createCalls int
	listCalls   int
	getCalls    int
	appInput    applications.ApplicationInput
	clientInput applications.ClientInput
	fingerprint applications.ProvisioningFingerprint
	requestID   string
	states      []applications.ProvisioningState
}

func (f *fakeApplicationManager) FindProvisioningCandidates(_ context.Context, fingerprint applications.ProvisioningFingerprint) ([]applications.ProvisioningState, error) {
	f.listCalls++
	f.fingerprint = fingerprint
	if f.states != nil {
		return f.states, nil
	}
	if !f.found {
		return nil, nil
	}
	state := applications.ProvisioningState{Application: f.detail.Application, Clients: f.detail.Clients}
	if f.duplicate {
		other := f.detail.Application
		other.ID = applications.ApplicationID("app_dreamup_duplicate")
		return []applications.ProvisioningState{state, {Application: other, Clients: f.detail.Clients}}, nil
	}
	return []applications.ProvisioningState{state}, nil
}

func (f *fakeApplicationManager) CreateWithInitialClient(
	_ context.Context,
	actor identity.UserID,
	requestID string,
	appInput applications.ApplicationInput,
	clientInput applications.ClientInput,
) (applications.CreateResult, error) {
	f.createCalls++
	f.appInput = appInput
	f.clientInput = clientInput
	f.requestID = requestID
	if f.createErr != nil {
		return applications.CreateResult{}, f.createErr
	}
	if actor != testOwnerID {
		return applications.CreateResult{}, errors.New("unexpected actor")
	}
	f.found = true
	f.detail = correctDetail()
	return applications.CreateResult{
		ApplicationID: testApplicationID,
		ClientID:      testClientID,
		ClientSecret:  testSecret,
	}, nil
}

type fakeProviderReader struct {
	snapshot  applications.ProviderClientSnapshot
	err       error
	readCalls int
	readID    string
}

type testCredentialSecurityPolicy struct{}

func (testCredentialSecurityPolicy) validateParent(string) error { return nil }

func (testCredentialSecurityPolicy) secureAndValidate(file *os.File) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o600 {
		return errors.New("unexpected test credential mode")
	}
	return nil
}

func (f *fakeProviderReader) ReadClient(_ context.Context, providerApplicationID string) (applications.ProviderClientSnapshot, error) {
	f.readCalls++
	f.readID = providerApplicationID
	return f.snapshot, f.err
}

func newService(manager *fakeApplicationManager, provider *fakeProviderReader) *Service {
	service := NewService(manager, manager, provider, ProviderExpectations{
		ProjectID:          testProjectID,
		InteractionBaseURI: testInteraction,
	})
	service.credentials = testCredentialSecurityPolicy{}
	return service
}

func correctDetail() applications.Detail {
	now := time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	return applications.Detail{
		Application: applications.Application{
			ID:           testApplicationID,
			Name:         ApplicationName,
			Description:  ApplicationDescription,
			Audience:     applications.AudienceExternal,
			OwnerID:      testOwnerID,
			Status:       applications.StatusActive,
			Provisioning: applications.ProvisioningStatusProvisioned,
			Version:      1,
			CreatedAt:    now,
			UpdatedAt:    now,
		},
		Clients: []applications.OAuthClient{{
			ID:                    testClientID,
			ApplicationID:         testApplicationID,
			Name:                  ClientName,
			Profile:               applications.ClientProfileWebServer,
			ClientType:            applications.ClientTypeConfidential,
			TokenEndpointAuth:     applications.TokenAuthClientSecretBasic,
			ConsentMode:           applications.ConsentModeFirstAuthorization,
			Status:                applications.StatusActive,
			RedirectURIs:          []applications.RedirectURI{{URI: RedirectURI, AddedAt: now}},
			LogoutURI:             LogoutURI,
			Scopes:                []string{"openid", "profile", "email"},
			Provider:              "zitadel",
			ProviderProjectID:     testProjectID,
			ProviderApplicationID: testProviderAppID,
			ProviderClientID:      testProviderID,
			Provisioning:          applications.ProvisioningStatusProvisioned,
			SecretRotationStatus:  applications.SecretRotationIdle,
			SecretRecords: []applications.ClientSecretRecord{{
				ID:        applications.ClientSecretID("sec_dreamup"),
				ClientID:  testClientID,
				CreatedAt: now,
			}},
			Version:   1,
			CreatedAt: now,
			UpdatedAt: now,
		}},
	}
}

func correctProviderSnapshot() applications.ProviderClientSnapshot {
	return applications.ProviderClientSnapshot{
		ProviderProjectID:     testProjectID,
		ProviderApplicationID: testProviderAppID,
		ProviderClientID:      testProviderID,
		DisplayName:           applications.ProviderDisplayName(ApplicationName, ClientName, testClientID),
		Profile:               applications.ClientProfileWebServer,
		TokenEndpointAuth:     applications.TokenAuthClientSecretBasic,
		Active:                true,
		RedirectURIs:          []string{RedirectURI},
		LogoutURIs:            []string{LogoutURI},
		ResponseTypes:         []applications.OAuthResponseType{applications.ResponseTypeCode},
		GrantTypes: []applications.OAuthGrantType{
			applications.GrantTypeAuthorizationCode,
			applications.GrantTypeRefreshToken,
		},
		LoginVersionBaseURI: testInteraction,
		DevMode:             false,
		OIDCVersion:         "1.0",
		AccessTokenType:     "bearer",
		AllowedOrigins:      []string{"https://moonstone.org.cn"},
	}
}

func execute(t *testing.T, svc *Service, opts Options) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exitCode := svc.Execute(context.Background(), opts, &stdout, &stderr)
	return exitCode, stdout.String(), stderr.String()
}

func TestExecuteCreatesDesiredSpecAndNeverPrintsSecret(t *testing.T) {
	manager := &fakeApplicationManager{}
	provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}
	secretPath := filepath.Join(t.TempDir(), "dreamup-client-secret")

	exitCode, stdout, stderr := execute(t, newService(manager, provider), Options{
		OwnerUserID:  testOwnerID,
		SecretOutput: secretPath,
	})

	if exitCode != 0 {
		t.Fatalf("Execute() exit = %d, stderr = %q", exitCode, stderr)
	}
	if manager.createCalls != 1 {
		t.Fatalf("CreateWithInitialClient calls = %d, want 1", manager.createCalls)
	}
	if !strings.HasPrefix(manager.requestID, BootstrapRequestPrefix) || len(manager.requestID) <= len(BootstrapRequestPrefix) {
		t.Fatalf("bootstrap request ID did not use the offline namespace")
	}
	wantFingerprint := applications.ProvisioningFingerprint{
		ApplicationName:        ApplicationName,
		ApplicationDescription: ApplicationDescription,
		ClientName:             ClientName,
		RedirectURI:            "https://moonstone.org.cn/moonstone-dreamup/auth/callback",
		LogoutURI:              "https://moonstone.org.cn/moonstone-dreamup/",
		BootstrapRequestPrefix: BootstrapRequestPrefix,
	}
	if manager.fingerprint != wantFingerprint {
		t.Fatalf("provisioning fingerprint = %#v, want %#v", manager.fingerprint, wantFingerprint)
	}
	if manager.appInput.Name != ApplicationName || manager.appInput.Description != ApplicationDescription ||
		manager.appInput.Audience != applications.AudienceExternal || manager.appInput.OwnerID != string(testOwnerID) {
		t.Fatalf("application input = %#v", manager.appInput)
	}
	wantTokenAuth := applications.TokenAuthClientSecretBasic
	gotClient := manager.clientInput
	if gotClient.Name != ClientName || gotClient.Profile != applications.ClientProfileWebServer ||
		gotClient.ConsentMode != applications.ConsentModeFirstAuthorization ||
		gotClient.LogoutURI != "https://moonstone.org.cn/moonstone-dreamup/" || len(gotClient.RedirectURIs) != 1 || gotClient.RedirectURIs[0] != "https://moonstone.org.cn/moonstone-dreamup/auth/callback" ||
		gotClient.TokenEndpointAuth == nil || *gotClient.TokenEndpointAuth != wantTokenAuth {
		t.Fatalf("client input = %#v", gotClient)
	}
	if strings.Join(gotClient.Scopes, " ") != "openid profile email" {
		t.Fatalf("scopes = %v", gotClient.Scopes)
	}
	if strings.Join([]string{string(gotClient.GrantTypes[0]), string(gotClient.GrantTypes[1])}, " ") != "authorization_code refresh_token" {
		t.Fatalf("grant types = %v", gotClient.GrantTypes)
	}
	if provider.readCalls != 1 || provider.readID != testProviderAppID {
		t.Fatalf("provider read = %d for %q", provider.readCalls, provider.readID)
	}
	if strings.Contains(stdout, testSecret) || strings.Contains(stderr, testSecret) {
		t.Fatal("client secret was printed")
	}
	for _, fragment := range []string{"status=created", "drift=none", string(testApplicationID), string(testClientID), testProviderAppID, testProviderID, "secret_provisioned=true"} {
		if !strings.Contains(stdout, fragment) {
			t.Errorf("stdout %q does not contain %q", stdout, fragment)
		}
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	secretBytes, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read secret output: %v", err)
	}
	if string(secretBytes) != testSecret {
		t.Fatalf("secret file did not contain the exact one-time secret")
	}
	info, err := os.Stat(secretPath)
	if err != nil {
		t.Fatalf("stat secret output: %v", err)
	}
	// Windows FileMode exposes only the read-only attribute, not an owner/
	// group/other ACL. The production target is Linux, where the exact mode
	// assertion is meaningful and mandatory.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("secret mode = %o, want 600", info.Mode().Perm())
	}
}

func TestExecuteAlreadyCorrectIsVerifiedWithZeroWrites(t *testing.T) {
	manager := &fakeApplicationManager{found: true, detail: correctDetail()}
	provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

	exitCode, stdout, stderr := execute(t, newService(manager, provider), Options{OwnerUserID: testOwnerID})

	if exitCode != 0 {
		t.Fatalf("Execute() exit = %d, stderr = %q", exitCode, stderr)
	}
	if manager.createCalls != 0 {
		t.Fatalf("existing correct state performed %d writes", manager.createCalls)
	}
	if provider.readCalls != 1 {
		t.Fatalf("provider read calls = %d, want 1", provider.readCalls)
	}
	if !strings.Contains(stdout, "status=verified") || !strings.Contains(stdout, "drift=none") {
		t.Fatalf("stdout = %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestExecuteRejectsExactRedirectDriftWithoutMutation(t *testing.T) {
	detail := correctDetail()
	detail.Clients[0].RedirectURIs[0].URI = "https://dreamup.moonstone.org.cn/auth/callback/"
	manager := &fakeApplicationManager{found: true, detail: detail}
	provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

	exitCode, _, stderr := execute(t, newService(manager, provider), Options{OwnerUserID: testOwnerID})

	if exitCode == 0 || !strings.Contains(stderr, "drift=redirect_uri") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	if manager.createCalls != 0 || provider.readCalls != 0 {
		t.Fatalf("drift performed mutation/read: creates=%d providerReads=%d", manager.createCalls, provider.readCalls)
	}
}

func TestExecuteRejectsWrongProfileWithoutMutation(t *testing.T) {
	detail := correctDetail()
	detail.Clients[0].Profile = applications.ClientProfileSPAMobile
	detail.Clients[0].ClientType = applications.ClientTypePublic
	detail.Clients[0].TokenEndpointAuth = applications.TokenAuthNone
	manager := &fakeApplicationManager{found: true, detail: detail}
	provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

	exitCode, _, stderr := execute(t, newService(manager, provider), Options{OwnerUserID: testOwnerID})

	if exitCode == 0 || !strings.Contains(stderr, "drift=profile") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	if manager.createCalls != 0 || provider.readCalls != 0 {
		t.Fatalf("profile drift performed mutation/read: creates=%d providerReads=%d", manager.createCalls, provider.readCalls)
	}
}

func TestExecuteRejectsLocalReconciliationOrSecretRotationDrift(t *testing.T) {
	tests := []struct {
		name  string
		field string
		drift func(*applications.OAuthClient)
	}{
		{
			name:  "provider reconciliation required",
			field: "client_provider_reconciliation",
			drift: func(c *applications.OAuthClient) { c.ProviderReconciliationRequired = true },
		},
		{
			name:  "secret rotation not idle",
			field: "client_secret_rotation",
			drift: func(c *applications.OAuthClient) { c.SecretRotationStatus = applications.SecretRotationOutcomeUnknown },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detail := correctDetail()
			tc.drift(&detail.Clients[0])
			manager := &fakeApplicationManager{found: true, detail: detail}
			provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

			exitCode, _, stderr := execute(t, newService(manager, provider), Options{OwnerUserID: testOwnerID})

			if exitCode == 0 || !strings.Contains(stderr, "drift="+tc.field) {
				t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
			}
			if manager.createCalls != 0 || provider.readCalls != 0 {
				t.Fatalf("local recovery drift touched dependencies: creates=%d providerReads=%d", manager.createCalls, provider.readCalls)
			}
		})
	}
}

func TestExecuteRejectsHiddenProvisioningStateWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(*applications.Detail)
	}{
		{
			name:  "application provisioning failed",
			field: "application_provisioning",
			mutate: func(detail *applications.Detail) {
				detail.Application.Provisioning = applications.ProvisioningStatusProvisioningFailed
			},
		},
		{
			name:  "extra failed client",
			field: "client_count",
			mutate: func(detail *applications.Detail) {
				extra := detail.Clients[0]
				extra.ID = applications.OAuthClientID("clt_hidden_failed")
				extra.Name = "Hidden failed client"
				extra.Provisioning = applications.ProvisioningStatusProvisioningFailed
				detail.Clients = append(detail.Clients, extra)
			},
		},
		{
			name:  "application soft deleted",
			field: "application_deleted",
			mutate: func(detail *applications.Detail) {
				deletedAt := time.Now().UTC()
				detail.Application.DeletedAt = &deletedAt
			},
		},
		{
			name:  "client soft deleted",
			field: "client_deleted",
			mutate: func(detail *applications.Detail) {
				deletedAt := time.Now().UTC()
				detail.Clients[0].DeletedAt = &deletedAt
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detail := correctDetail()
			tc.mutate(&detail)
			manager := &fakeApplicationManager{found: true, detail: detail}
			provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

			exitCode, _, stderr := execute(t, newService(manager, provider), Options{OwnerUserID: testOwnerID})

			if exitCode == 0 || !strings.Contains(stderr, "drift="+tc.field) {
				t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
			}
			if manager.createCalls != 0 || provider.readCalls != 0 {
				t.Fatalf("hidden state touched dependencies: creates=%d providerReads=%d", manager.createCalls, provider.readCalls)
			}
		})
	}
}

func TestExecuteFailsWhenProviderReadbackIsMissing(t *testing.T) {
	manager := &fakeApplicationManager{found: true, detail: correctDetail()}
	provider := &fakeProviderReader{err: applications.ErrProviderConflict}

	exitCode, stdout, stderr := execute(t, newService(manager, provider), Options{OwnerUserID: testOwnerID})

	if exitCode == 0 || !strings.Contains(stderr, "drift=provider_readback") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	if manager.createCalls != 0 {
		t.Fatalf("missing provider readback performed %d writes", manager.createCalls)
	}
	if strings.Contains(stdout, testSecret) || strings.Contains(stderr, testSecret) {
		t.Fatal("client secret was printed")
	}
}

func TestExecuteRejectsProviderRedirectDriftWithoutMutation(t *testing.T) {
	snapshot := correctProviderSnapshot()
	snapshot.RedirectURIs = []string{"https://dreamup.moonstone.org.cn/auth/callback/"}
	manager := &fakeApplicationManager{found: true, detail: correctDetail()}
	provider := &fakeProviderReader{snapshot: snapshot}

	exitCode, _, stderr := execute(t, newService(manager, provider), Options{OwnerUserID: testOwnerID})

	if exitCode == 0 || !strings.Contains(stderr, "drift=provider_redirect_uri") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	if manager.createCalls != 0 {
		t.Fatalf("provider drift performed %d writes", manager.createCalls)
	}
}

func TestExecuteRejectsPreservedProviderConfigurationDrift(t *testing.T) {
	tests := []struct {
		name  string
		field string
		drift func(*applications.ProviderClientSnapshot)
	}{
		{name: "oidc version", field: "provider_oidc_version", drift: func(s *applications.ProviderClientSnapshot) { s.OIDCVersion = "provider_unknown" }},
		{name: "access token type", field: "provider_access_token_type", drift: func(s *applications.ProviderClientSnapshot) { s.AccessTokenType = "jwt" }},
		{name: "non compliant", field: "provider_compliance", drift: func(s *applications.ProviderClientSnapshot) { s.NonCompliant = true }},
		{name: "access token role assertion", field: "provider_access_token_role_assertion", drift: func(s *applications.ProviderClientSnapshot) { s.AccessTokenRoleAssertion = true }},
		{name: "id token role assertion", field: "provider_id_token_role_assertion", drift: func(s *applications.ProviderClientSnapshot) { s.IDTokenRoleAssertion = true }},
		{name: "id token userinfo assertion", field: "provider_id_token_userinfo_assertion", drift: func(s *applications.ProviderClientSnapshot) { s.IDTokenUserinfoAssertion = true }},
		{name: "clock skew", field: "provider_clock_skew", drift: func(s *applications.ProviderClientSnapshot) { s.ClockSkewNanoseconds = 1 }},
		{name: "additional origins", field: "provider_additional_origins", drift: func(s *applications.ProviderClientSnapshot) {
			s.AdditionalOrigins = []string{"https://unexpected.example"}
		}},
		{name: "native success page", field: "provider_native_success_page", drift: func(s *applications.ProviderClientSnapshot) { s.SkipNativeAppSuccessPage = true }},
		{name: "back-channel logout", field: "provider_backchannel_logout", drift: func(s *applications.ProviderClientSnapshot) {
			s.BackChannelLogoutURI = "https://unexpected.example/logout"
		}},
		{name: "allowed origins", field: "provider_allowed_origins", drift: func(s *applications.ProviderClientSnapshot) {
			s.AllowedOrigins = []string{"https://unexpected.example"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := correctProviderSnapshot()
			tc.drift(&snapshot)
			manager := &fakeApplicationManager{found: true, detail: correctDetail()}
			provider := &fakeProviderReader{snapshot: snapshot}

			exitCode, _, stderr := execute(t, newService(manager, provider), Options{OwnerUserID: testOwnerID})

			if exitCode == 0 || !strings.Contains(stderr, "drift="+tc.field) {
				t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
			}
			if manager.createCalls != 0 {
				t.Fatalf("provider drift performed %d writes", manager.createCalls)
			}
		})
	}
}

func TestExecuteReportsDuplicateApplicationAsDriftWithoutMutation(t *testing.T) {
	manager := &fakeApplicationManager{found: true, duplicate: true, detail: correctDetail()}
	provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

	exitCode, _, stderr := execute(t, newService(manager, provider), Options{OwnerUserID: testOwnerID})

	if exitCode == 0 || !strings.Contains(stderr, "drift=application_count") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	if manager.createCalls != 0 || provider.readCalls != 0 {
		t.Fatalf("duplicate applications performed mutation/read: creates=%d providerReads=%d", manager.createCalls, provider.readCalls)
	}
}

func TestExecutePrefersDurableBootstrapAnchorOverMarkerCollision(t *testing.T) {
	target := correctDetail()
	collision := correctDetail()
	collision.Application.ID = applications.ApplicationID("app_unrelated_collision")
	collision.Application.Name = "Unrelated application"
	collision.Application.Description = "Unrelated description"
	collision.Clients[0].ID = applications.OAuthClientID("clt_unrelated_collision")
	collision.Clients[0].ApplicationID = collision.Application.ID
	manager := &fakeApplicationManager{states: []applications.ProvisioningState{
		{Application: target.Application, Clients: target.Clients, BootstrapAnchored: true},
		{Application: collision.Application, Clients: collision.Clients},
	}}
	provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

	exitCode, stdout, stderr := execute(t, newService(manager, provider), Options{OwnerUserID: testOwnerID})

	if exitCode != 0 || !strings.Contains(stdout, "status=verified") || stderr != "" {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", exitCode, stdout, stderr)
	}
	if manager.createCalls != 0 || provider.readCalls != 1 {
		t.Fatalf("anchor precedence touched wrong dependencies: creates=%d providerReads=%d", manager.createCalls, provider.readCalls)
	}
}

func TestExecuteReportsRenamedApplicationAsDriftWithoutMutation(t *testing.T) {
	detail := correctDetail()
	detail.Application.Name = "Renamed DreamUP"
	manager := &fakeApplicationManager{found: true, detail: detail}
	provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

	exitCode, _, stderr := execute(t, newService(manager, provider), Options{OwnerUserID: testOwnerID})

	if exitCode == 0 || !strings.Contains(stderr, "drift=application_name") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	if manager.createCalls != 0 || provider.readCalls != 0 {
		t.Fatalf("renamed application performed mutation/read: creates=%d providerReads=%d", manager.createCalls, provider.readCalls)
	}
}

func TestExecuteRequiresOwnerBeforeAnyReadOrWrite(t *testing.T) {
	manager := &fakeApplicationManager{}
	provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

	exitCode, _, stderr := execute(t, newService(manager, provider), Options{})

	if exitCode == 0 || !strings.Contains(stderr, "error=owner_user_id_required") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	if manager.listCalls != 0 || manager.createCalls != 0 || provider.readCalls != 0 {
		t.Fatalf("missing owner touched dependencies: list=%d create=%d provider=%d", manager.listCalls, manager.createCalls, provider.readCalls)
	}
}

func TestExecuteRequiresAbsoluteSecretOutputBeforeFirstWrite(t *testing.T) {
	for _, output := range []string{"", "relative-secret"} {
		t.Run(output, func(t *testing.T) {
			manager := &fakeApplicationManager{}
			provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

			exitCode, _, stderr := execute(t, newService(manager, provider), Options{
				OwnerUserID:  testOwnerID,
				SecretOutput: output,
			})

			if exitCode == 0 || !strings.Contains(stderr, "error=secret_output_required") {
				t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
			}
			if manager.createCalls != 0 || provider.readCalls != 0 {
				t.Fatalf("missing/relative output touched mutation: creates=%d provider=%d", manager.createCalls, provider.readCalls)
			}
		})
	}
}

func TestExecuteFailsClosedWhenBootstrapIdentityEntropyFails(t *testing.T) {
	original := requestIDEntropy
	requestIDEntropy = strings.NewReader("")
	t.Cleanup(func() { requestIDEntropy = original })

	secretPath := filepath.Join(t.TempDir(), "must-not-survive")
	manager := &fakeApplicationManager{}
	provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

	exitCode, stdout, stderr := execute(t, newService(manager, provider), Options{
		OwnerUserID:  testOwnerID,
		SecretOutput: secretPath,
	})

	if exitCode == 0 || !strings.Contains(stderr, "error=verification_failed") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	if manager.createCalls != 0 || provider.readCalls != 0 {
		t.Fatalf("entropy failure touched dependencies: creates=%d provider=%d", manager.createCalls, provider.readCalls)
	}
	if _, err := os.Stat(secretPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reserved credential survived entropy failure: %v", err)
	}
	if strings.Contains(stdout, testSecret) || strings.Contains(stderr, testSecret) {
		t.Fatal("entropy failure leaked secret")
	}
}

func TestExecuteRefusesToOverwriteSecretOutputBeforeFirstWrite(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "existing-secret")
	if err := os.WriteFile(secretPath, []byte("operator-owned-existing-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := &fakeApplicationManager{}
	provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

	exitCode, _, stderr := execute(t, newService(manager, provider), Options{
		OwnerUserID:  testOwnerID,
		SecretOutput: secretPath,
	})

	if exitCode == 0 || !strings.Contains(stderr, "error=secret_output_unavailable") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	if manager.createCalls != 0 || provider.readCalls != 0 {
		t.Fatalf("overwrite refusal touched mutation: creates=%d provider=%d", manager.createCalls, provider.readCalls)
	}
	got, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "operator-owned-existing-content" {
		t.Fatal("existing secret output was overwritten")
	}
}

func TestExecuteRedactsSecretFromDependencyErrors(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "dreamup-client-secret")
	manager := &fakeApplicationManager{createErr: errors.New("provider accidentally returned " + testSecret)}
	provider := &fakeProviderReader{snapshot: correctProviderSnapshot()}

	exitCode, stdout, stderr := execute(t, newService(manager, provider), Options{
		OwnerUserID:  testOwnerID,
		SecretOutput: secretPath,
	})

	if exitCode == 0 {
		t.Fatal("Execute() succeeded despite dependency error")
	}
	if strings.Contains(stdout, testSecret) || strings.Contains(stderr, testSecret) {
		t.Fatal("dependency error leaked the client secret")
	}
	if !strings.Contains(stderr, "error=provisioning_failed") {
		t.Fatalf("stderr = %q", stderr)
	}
	if _, err := os.Stat(secretPath); !os.IsNotExist(err) {
		t.Fatalf("reserved output survived failed creation: %v", err)
	}
}

func TestExecutePreservesSecretFileWhenPostCreateVerificationFails(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "dreamup-client-secret")
	manager := &fakeApplicationManager{}
	provider := &fakeProviderReader{err: applications.ErrProviderUnavailable}

	exitCode, stdout, stderr := execute(t, newService(manager, provider), Options{
		OwnerUserID:  testOwnerID,
		SecretOutput: secretPath,
	})

	if exitCode == 0 || !strings.Contains(stderr, "drift=provider_readback") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	if strings.Contains(stdout, testSecret) || strings.Contains(stderr, testSecret) {
		t.Fatal("post-create verification failure printed the client secret")
	}
	secretBytes, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read quarantined secret output: %v", err)
	}
	if string(secretBytes) != testSecret {
		t.Fatal("post-create verification failure did not preserve the exact one-time secret")
	}
}
