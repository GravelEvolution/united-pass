package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/GravelEvolution/united-pass/backend/internal/config"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

// NewSDKClient builds the ZITADEL gRPC client authenticated as the configured
// service account (OAuth2 JWT profile grant). The base URL must be HTTPS in
// production; an explicit http:// base URL (local test instances) enables the
// SDK's insecure mode.
func NewSDKClient(ctx context.Context, cfg config.AuthProviderConfig) (*client.Client, error) {
	key, err := loadServiceAccountKey(cfg.ServiceAccountKeyFile)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("zitadel: parse base url: %w", err)
	}

	host := u.Hostname()
	var conf *zitadel.Zitadel
	if u.Scheme == "http" {
		port := u.Port()
		if port == "" {
			port = "80"
		}
		conf = zitadel.New(host, zitadel.WithInsecure(port))
	} else {
		conf = zitadel.New(host)
	}

	// The JWT profile token is minted for the ZITADEL API audience; the same
	// token authorizes the session and user service calls.
	c, err := client.New(ctx, conf,
		client.WithAuth(client.AuthenticationJWTProfile(key, client.ScopeZitadelAPI())))
	if err != nil {
		return nil, fmt.Errorf("zitadel: create client: %w", err)
	}
	return c, nil
}

// loadServiceAccountKey reads and validates the ZITADEL service account
// key.json file.
func loadServiceAccountKey(path string) (*client.KeyFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("zitadel: read service account key file: %w", err)
	}
	var key client.KeyFile
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, fmt.Errorf("zitadel: parse service account key file: %w", err)
	}
	if key.KeyID == "" || len(key.Key) == 0 || key.UserID == "" {
		return nil, errors.New("zitadel: service account key file must contain keyId, key and userId")
	}
	return &key, nil
}
