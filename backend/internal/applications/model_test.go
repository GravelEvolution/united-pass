//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the applications domain model
//

package applications

import (
	"strings"
	"testing"
)

func TestTypedIDGeneration(t *testing.T) {
	app1, app2 := NewApplicationID(), NewApplicationID()
	if !strings.HasPrefix(string(app1), "app_") || !strings.HasPrefix(string(app2), "app_") {
		t.Errorf("application IDs must use the app_ prefix: %s, %s", app1, app2)
	}
	if app1 == app2 {
		t.Error("generated application IDs must be unique")
	}
	if len(string(app1)) != len("app_")+32 {
		t.Errorf("application ID length = %d, want %d", len(string(app1)), len("app_")+32)
	}

	if !strings.HasPrefix(string(NewOAuthClientID()), "clt_") {
		t.Error("client IDs must use the clt_ prefix")
	}
	if !strings.HasPrefix(string(NewClientSecretID()), "sec_") {
		t.Error("secret IDs must use the sec_ prefix")
	}
	if !strings.HasPrefix(string(NewProviderOperationID()), "op_") {
		t.Error("operation IDs must use the op_ prefix")
	}
}

func TestIDPrefixChecks(t *testing.T) {
	if !HasApplicationIDPrefix("app_abc") || HasApplicationIDPrefix("clt_abc") || HasApplicationIDPrefix("app_") {
		t.Error("HasApplicationIDPrefix misbehaves")
	}
	if !HasOAuthClientIDPrefix("clt_abc") || HasOAuthClientIDPrefix("app_abc") || HasOAuthClientIDPrefix("clt_") {
		t.Error("HasOAuthClientIDPrefix misbehaves")
	}
}

func TestProfileRules(t *testing.T) {
	web, ok := ClientProfileWebServer.Rules()
	if !ok {
		t.Fatal("web_server rules missing")
	}
	if web.ClientType != ClientTypeConfidential || web.TokenEndpointAuth != TokenAuthClientSecretBasic {
		t.Errorf("web_server rules wrong: %+v", web)
	}
	if !web.HasGrantType(GrantTypeAuthorizationCode) || !web.HasGrantType(GrantTypeRefreshToken) {
		t.Errorf("web_server grant types wrong: %+v", web.GrantTypes)
	}
	if !web.RedirectURIRequired || !web.SupportsSecret || !web.OpenIDAllowed {
		t.Errorf("web_server flags wrong: %+v", web)
	}

	spa, ok := ClientProfileSPAMobile.Rules()
	if !ok {
		t.Fatal("spa_mobile rules missing")
	}
	if spa.ClientType != ClientTypePublic || spa.TokenEndpointAuth != TokenAuthNone {
		t.Errorf("spa_mobile rules wrong: %+v", spa)
	}
	if spa.SupportsSecret {
		t.Error("public clients must never support secrets")
	}

	s2s, ok := ClientProfileServerToServer.Rules()
	if !ok {
		t.Fatal("server_to_server rules missing")
	}
	if !s2s.HasGrantType(GrantTypeClientCredentials) || s2s.HasGrantType(GrantTypeAuthorizationCode) {
		t.Errorf("server_to_server grant types wrong: %+v", s2s.GrantTypes)
	}
	if s2s.RedirectURIRequired || s2s.OpenIDAllowed || s2s.ConsentApplicable {
		t.Errorf("server_to_server flags wrong: %+v", s2s)
	}

	if _, ok := ClientProfile("desktop").Rules(); ok {
		t.Error("unknown profile must not yield rules")
	}
	if ClientProfile("desktop").IsValid() {
		t.Error("unknown profile reported valid")
	}
}

func TestStatusTransitions(t *testing.T) {
	app := &Application{Status: StatusActive}
	if err := app.Enable(); err != ErrInvalidStateTransition {
		t.Errorf("Enable on active app: err = %v, want ErrInvalidStateTransition", err)
	}
	if err := app.Disable(); err != nil {
		t.Fatalf("Disable on active app failed: %v", err)
	}
	if app.Status != StatusDisabled {
		t.Fatalf("status = %s, want disabled", app.Status)
	}
	if err := app.Disable(); err != ErrInvalidStateTransition {
		t.Errorf("Disable on disabled app: err = %v, want ErrInvalidStateTransition", err)
	}
	if err := app.Enable(); err != nil {
		t.Fatalf("Enable on disabled app failed: %v", err)
	}

	client := &OAuthClient{ClientType: ClientTypePublic, Status: StatusActive}
	if client.CanRotateSecret() {
		t.Error("public client must never rotate secrets")
	}
	confidential := &OAuthClient{ClientType: ClientTypeConfidential, Status: StatusActive}
	if !confidential.CanRotateSecret() {
		t.Error("active confidential client must be able to rotate secrets")
	}
	confidential.Status = StatusDisabled
	if confidential.CanRotateSecret() {
		t.Error("disabled client must not rotate secrets")
	}
}
