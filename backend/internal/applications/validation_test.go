package applications

import (
	"strings"
	"testing"
)

func TestValidateRedirectURI(t *testing.T) {
	valid := []struct {
		uri        string
		isLoopback bool
	}{
		{"https://app.example.com/callback", false},
		{"https://app.example.com:8443/cb?x=1", false},
		{"http://localhost/callback", true},
		{"http://localhost:3000/callback", true},
		{"http://127.0.0.1/callback", true},
		{"http://127.0.0.1:5173/", true},
		{"http://[::1]:8080/cb", true},
	}
	for _, tc := range valid {
		lb, ok := ValidateRedirectURI(tc.uri)
		if !ok {
			t.Errorf("ValidateRedirectURI(%q) = invalid, want valid", tc.uri)
			continue
		}
		if lb != tc.isLoopback {
			t.Errorf("ValidateRedirectURI(%q) loopback = %v, want %v", tc.uri, lb, tc.isLoopback)
		}
	}

	invalid := []string{
		"",
		"   ",
		" app.example.com/callback",
		"/relative/path",
		"http://app.example.com/callback",    // plain http non-loopback
		"http://intranet.local/callback",     // plain http non-loopback
		"https://app.example.com/cb#frag",    // fragment
		"https://user:pass@example.com/cb",   // userinfo
		"https://app.example.com/*/callback", // wildcard
		"myapp://callback",                   // custom scheme not supported in MVP
		"ftp://example.com/cb",
		"https://" + strings.Repeat("a", MaxRedirectURILen) + ".example.com/cb", // too long
	}
	for _, uri := range invalid {
		if _, ok := ValidateRedirectURI(uri); ok {
			t.Errorf("ValidateRedirectURI(%q) = valid, want invalid", uri)
		}
	}
}

func TestValidateClientInputWebServer(t *testing.T) {
	in := ClientInput{
		Name:         "Web 服务端客户端",
		Profile:      ClientProfileWebServer,
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
		ConsentMode:  ConsentModeAlways,
	}
	if err := ValidateClientInput(in); err != nil {
		t.Fatalf("valid web_server input rejected: %v", err)
	}
}

func TestValidateClientInputServerToServer(t *testing.T) {
	in := ClientInput{
		Name:         "服务账号",
		Profile:      ClientProfileServerToServer,
		RedirectURIs: nil,
		Scopes:       []string{"reporting:read"},
		ConsentMode:  ConsentModeAlways,
	}
	if err := ValidateClientInput(in); err != nil {
		t.Fatalf("valid server_to_server input rejected: %v", err)
	}
}

func TestValidateClientInputRejectsInvalidCombinations(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*ClientInput)
		wantField string
	}{
		{
			name:      "unknown profile",
			mutate:    func(in *ClientInput) { in.Profile = ClientProfile("desktop") },
			wantField: "profile",
		},
		{
			name: "server_to_server with redirect uri",
			mutate: func(in *ClientInput) {
				in.Profile = ClientProfileServerToServer
				in.RedirectURIs = []string{"https://a.example.com/cb"}
			},
			wantField: "redirectUris",
		},
		{
			name:      "server_to_server with openid",
			mutate:    func(in *ClientInput) { in.Profile = ClientProfileServerToServer; in.Scopes = []string{"openid"} },
			wantField: "allowedScopes",
		},
		{
			name: "server_to_server with offline_access",
			mutate: func(in *ClientInput) {
				in.Profile = ClientProfileServerToServer
				in.Scopes = []string{"offline_access"}
			},
			wantField: "allowedScopes",
		},
		{
			name: "server_to_server first_authorization consent",
			mutate: func(in *ClientInput) {
				in.Profile = ClientProfileServerToServer
				in.ConsentMode = ConsentModeFirstAuthorization
			},
			wantField: "consentMode",
		},
		{
			name:      "trusted_first_party consent rejected",
			mutate:    func(in *ClientInput) { in.ConsentMode = ConsentMode("trusted_first_party") },
			wantField: "consentMode",
		},
		{
			name:      "web_server without redirect uri",
			mutate:    func(in *ClientInput) { in.RedirectURIs = nil },
			wantField: "redirectUris",
		},
		{
			name: "duplicate redirect uri",
			mutate: func(in *ClientInput) {
				in.RedirectURIs = []string{"https://a.example.com/cb", "https://a.example.com/cb"}
			},
			wantField: "redirectUris[1]",
		},
		{
			name: "duplicate scope",
			mutate: func(in *ClientInput) {
				in.Scopes = []string{"openid", "openid"}
			},
			wantField: "allowedScopes",
		},
		{
			name:      "unknown scope",
			mutate:    func(in *ClientInput) { in.Scopes = []string{"admin:all"} },
			wantField: "allowedScopes",
		},
		{
			name:      "short name",
			mutate:    func(in *ClientInput) { in.Name = "x" },
			wantField: "name",
		},
		{
			name:      "client_credentials grant on web_server",
			mutate:    func(in *ClientInput) { in.GrantTypes = []OAuthGrantType{GrantTypeClientCredentials} },
			wantField: "grantTypes",
		},
		{
			name: "client_secret_post rejected",
			mutate: func(in *ClientInput) {
				m := TokenEndpointAuthMethod("client_secret_post")
				in.TokenEndpointAuth = &m
			},
			wantField: "tokenEndpointAuthMethod",
		},
		{
			name: "private_key_jwt rejected",
			mutate: func(in *ClientInput) {
				m := TokenEndpointAuthMethod("private_key_jwt")
				in.TokenEndpointAuth = &m
			},
			wantField: "tokenEndpointAuthMethod",
		},
	}

	base := func() ClientInput {
		return ClientInput{
			Name:         "有效客户端",
			Profile:      ClientProfileWebServer,
			RedirectURIs: []string{"https://a.example.com/cb"},
			Scopes:       []string{"openid"},
			ConsentMode:  ConsentModeAlways,
		}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			tc.mutate(&in)
			err := ValidateClientInput(in)
			if err == nil {
				t.Fatalf("expected validation error on field %s, got nil", tc.wantField)
			}
			var verrs *ValidationErrors
			verrs, ok := err.(*ValidationErrors)
			if !ok {
				t.Fatalf("expected *ValidationErrors, got %T", err)
			}
			found := false
			for _, fe := range verrs.Errors {
				if fe.Field == tc.wantField {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected field error %q, got %+v", tc.wantField, verrs.Errors)
			}
		})
	}
}

func TestValidateClientInputTooManyRedirectURIs(t *testing.T) {
	in := ClientInput{
		Name:        "uri 超限",
		Profile:     ClientProfileWebServer,
		Scopes:      []string{"openid"},
		ConsentMode: ConsentModeAlways,
	}
	for i := 0; i < MaxRedirectURIs+1; i++ {
		in.RedirectURIs = append(in.RedirectURIs, "https://a.example.com/cb")
	}
	err := ValidateClientInput(in)
	if err == nil {
		t.Fatal("expected validation error for too many redirect URIs")
	}
}

func TestValidateApplicationInput(t *testing.T) {
	valid := ApplicationInput{
		Name:     "United Workspace",
		Audience: AudienceExternal,
		OwnerID:  "user_abc",
	}
	if err := ValidateApplicationInput(valid); err != nil {
		t.Fatalf("valid application input rejected: %v", err)
	}

	invalid := ApplicationInput{Name: "x", Audience: ApplicationAudience("mars"), OwnerID: "  "}
	err := ValidateApplicationInput(invalid)
	if err == nil {
		t.Fatal("expected validation errors")
	}
	verrs := err.(*ValidationErrors)
	fields := map[string]bool{}
	for _, fe := range verrs.Errors {
		fields[fe.Field] = true
	}
	for _, want := range []string{"name", "audience", "ownerId"} {
		if !fields[want] {
			t.Errorf("expected field error %q, got %+v", want, verrs.Errors)
		}
	}
}

func TestScopeCatalogMatchesFrontendContract(t *testing.T) {
	want := []string{"openid", "profile", "email", "phone", "offline_access", "reporting:read"}
	if len(ScopeCatalog) != len(want) {
		t.Fatalf("catalog size = %d, want %d", len(ScopeCatalog), len(want))
	}
	for i, def := range ScopeCatalog {
		if def.Scope != want[i] {
			t.Errorf("catalog[%d] = %q, want %q", i, def.Scope, want[i])
		}
		if def.Label == "" || def.Description == "" {
			t.Errorf("catalog[%d] missing label/description", i)
		}
	}
	if KnownScope("admin:all") {
		t.Error("unregistered scope reported as known")
	}
}
