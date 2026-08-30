//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Non-secret provider client read-back verification tests
//

package zitadel

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"

	appv1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/app"
	management "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestProvisionerReadClientReturnsCompleteNonSecretSnapshot(t *testing.T) {
	baseURI := "https://pass.moonstone.org.cn/_interaction"
	stub := &stubManagement{getResp: &management.GetAppByIDResponse{App: &appv1.App{
		Id:    "provider-app-dreamup",
		Name:  "MoonStone DreamUP · DreamUP Web · dreamup",
		State: appv1.AppState_APP_STATE_ACTIVE,
		Config: &appv1.App_OidcConfig{OidcConfig: &appv1.OIDCConfig{
			ClientId:                 "provider-client-dreamup",
			RedirectUris:             []string{"https://dreamup.moonstone.org.cn/auth/callback"},
			PostLogoutRedirectUris:   []string{"https://dreamup.moonstone.org.cn/"},
			ResponseTypes:            []appv1.OIDCResponseType{appv1.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
			GrantTypes:               []appv1.OIDCGrantType{appv1.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE, appv1.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN},
			AppType:                  appv1.OIDCAppType_OIDC_APP_TYPE_WEB,
			AuthMethodType:           appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC,
			Version:                  appv1.OIDCVersion_OIDC_VERSION_1_0,
			AccessTokenType:          appv1.OIDCTokenType_OIDC_TOKEN_TYPE_JWT,
			DevMode:                  false,
			LoginVersion:             loginV2Fixture(baseURI),
			NoneCompliant:            true,
			IdTokenRoleAssertion:     true,
			IdTokenUserinfoAssertion: true,
			AccessTokenRoleAssertion: true,
			ClockSkew:                durationpb.New(2 * time.Second),
			SkipNativeAppSuccessPage: true,
			AdditionalOrigins:        []string{"https://extra.example"},
			BackChannelLogoutUri:     "https://extra.example/backchannel",
			AllowedOrigins:           []string{"https://effective.example"},
		}},
	}}}
	provisioner, err := NewProvisioner(stub, "provider-project", baseURI, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := provisioner.ReadClient(context.Background(), "provider-app-dreamup")
	if err != nil {
		t.Fatalf("ReadClient() error = %v", err)
	}
	want := applications.ProviderClientSnapshot{
		ProviderProjectID:     "provider-project",
		ProviderApplicationID: "provider-app-dreamup",
		ProviderClientID:      "provider-client-dreamup",
		DisplayName:           "MoonStone DreamUP · DreamUP Web · dreamup",
		Profile:               applications.ClientProfileWebServer,
		TokenEndpointAuth:     applications.TokenAuthClientSecretBasic,
		Active:                true,
		RedirectURIs:          []string{"https://dreamup.moonstone.org.cn/auth/callback"},
		LogoutURIs:            []string{"https://dreamup.moonstone.org.cn/"},
		ResponseTypes:         []applications.OAuthResponseType{applications.ResponseTypeCode},
		GrantTypes: []applications.OAuthGrantType{
			applications.GrantTypeAuthorizationCode,
			applications.GrantTypeRefreshToken,
		},
		LoginVersionBaseURI:      baseURI,
		DevMode:                  false,
		OIDCVersion:              applications.OIDCVersion10,
		AccessTokenType:          applications.AccessTokenTypeJWT,
		NonCompliant:             true,
		AccessTokenRoleAssertion: true,
		IDTokenRoleAssertion:     true,
		IDTokenUserinfoAssertion: true,
		ClockSkewNanoseconds:     int64(2 * time.Second),
		AdditionalOrigins:        []string{"https://extra.example"},
		SkipNativeAppSuccessPage: true,
		BackChannelLogoutURI:     "https://extra.example/backchannel",
		AllowedOrigins:           []string{"https://effective.example"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadClient() = %#v, want %#v", got, want)
	}
	if stub.added != 0 || stub.updateAppReq != nil || stub.updateCfgCount != 0 ||
		stub.deactivated != 0 || stub.reactivated != 0 || stub.removed != 0 {
		t.Fatal("provider read-back performed a mutation")
	}
}

func TestProvisionerReadClientMissingProviderReadbackFailsWithoutRawDetail(t *testing.T) {
	raw := status.Error(codes.NotFound, "sensitive-provider-detail")
	provisioner := newTestProvisioner(t, &stubManagement{getErr: raw})

	_, err := provisioner.ReadClient(context.Background(), "missing-provider-app")

	if !errors.Is(err, applications.ErrProviderConflict) {
		t.Fatalf("ReadClient() error = %v, want provider conflict", err)
	}
	if strings.Contains(err.Error(), "sensitive-provider-detail") {
		t.Fatal("provider read-back error leaked raw provider detail")
	}
}
