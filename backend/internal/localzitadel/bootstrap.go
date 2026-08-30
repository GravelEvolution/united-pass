// Package localzitadel bootstraps the disposable, loopback-only ZITADEL
// instance used by United Pass integration tests.
package localzitadel

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP requires HMAC-SHA-1.
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultBaseURL     = "http://localhost:8080"
	defaultTestUser    = "zhixing.lin"
	defaultProjectName = "United Pass Local E2E"
	maxResponseBytes   = 4 << 20
)

// Config contains only local-development bootstrap settings. BaseURL is
// deliberately restricted to a bare loopback URL by Run.
type Config struct {
	BaseURL       string
	OutDir        string
	InitKeyFile   string
	TestUser      string
	TestPassword  string
	TestFirstName string
	TestLastName  string
	TestDisplay   string
	ProjectName   string
	ReadyTimeout  time.Duration
	RetryInterval time.Duration
	Output        io.Writer
	Now           func() time.Time
	Random        io.Reader
}

// Result deliberately excludes passwords, private keys, tokens and TOTP
// material. Callers may safely log this value.
type Result struct {
	BaseURL       string
	StateFile     string
	ServiceKey    string
	UserLogin     string
	UserID        string
	Organization  string
	ProjectID     string
	ServiceUserID string
}

type state struct {
	BaseURL          string `json:"baseUrl"`
	KeyFile          string `json:"keyFile"`
	User             string `json:"user"`
	Password         string `json:"password"`
	UserID           string `json:"userId"`
	TOTPSecret       string `json:"totpSecret"`
	OrganizationID   string `json:"organizationId"`
	ProjectID        string `json:"projectId"`
	ServiceAccountID string `json:"serviceAccountUserId"`
}

type serviceAccountKey struct {
	Type           json.RawMessage `json:"type"`
	KeyID          string          `json:"keyId"`
	PrivateKeyPEM  string          `json:"key"`
	ExpirationDate string          `json:"expirationDate"`
	UserID         string          `json:"userId"`
}

type client struct {
	base  *url.URL
	http  *http.Client
	token string
}

type httpStatusError struct {
	Method string
	Path   string
	Status int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("ZITADEL %s %s returned HTTP %d", e.Method, e.Path, e.Status)
}

// Run idempotently creates the local test identity, TOTP factor, backend
// service account, service-account key and provisioning project.
func Run(ctx context.Context, cfg Config) (Result, error) {
	cfg = withDefaults(cfg)
	base, err := validateLoopbackBaseURL(cfg.BaseURL)
	if err != nil {
		return Result{}, err
	}
	if cfg.OutDir == "" {
		return Result{}, errors.New("local ZITADEL output directory is required")
	}
	absOut, err := filepath.Abs(cfg.OutDir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve local ZITADEL output directory: %w", err)
	}
	if err := os.MkdirAll(absOut, 0o700); err != nil {
		return Result{}, fmt.Errorf("create local ZITADEL output directory: %w", err)
	}
	if err := rejectSymlink(absOut); err != nil {
		return Result{}, err
	}

	stateFile := filepath.Join(absOut, "init-state.json")
	serviceKeyFile := filepath.Join(absOut, "sa-key.json")
	initKeyFile := cfg.InitKeyFile
	if initKeyFile == "" {
		initKeyFile = filepath.Join(absOut, "init-sa.json")
	}
	initKeyFile, err = filepath.Abs(initKeyFile)
	if err != nil {
		return Result{}, fmt.Errorf("resolve initializer key path: %w", err)
	}

	previous, hasPrevious, err := readState(stateFile)
	if err != nil {
		return Result{}, err
	}
	password := cfg.TestPassword
	if password == "" && hasPrevious {
		password = previous.Password
	}
	if password == "" {
		password, err = generatePassword(cfg.Random)
		if err != nil {
			return Result{}, err
		}
	}
	if err := validatePassword(password); err != nil {
		return Result{}, err
	}

	httpClient := newLoopbackHTTPClient(15 * time.Second)
	z := &client{base: base, http: httpClient}
	logf(cfg.Output, "waiting for the loopback ZITADEL instance")
	if err := z.waitReady(ctx, cfg.ReadyTimeout, cfg.RetryInterval); err != nil {
		return Result{}, err
	}

	initKey, privateKey, err := loadServiceAccountKey(initKeyFile)
	if err != nil {
		return Result{}, fmt.Errorf("load local initializer service-account key: %w", err)
	}
	assertion, err := signJWTAssertion(initKey, privateKey, base.String(), cfg.Now(), cfg.Random)
	if err != nil {
		return Result{}, fmt.Errorf("sign local initializer assertion: %w", err)
	}
	z.token, err = z.exchangeJWT(ctx, assertion)
	if err != nil {
		return Result{}, fmt.Errorf("acquire local initializer token: %w", err)
	}
	logf(cfg.Output, "authenticated the local initializer")

	users, err := z.listUsers(ctx)
	if err != nil {
		return Result{}, err
	}
	testHuman, ok := findUser(users, cfg.TestUser)
	if !ok {
		logf(cfg.Output, "creating the local integration-test user")
		userID, createErr := z.createHuman(ctx, cfg, password)
		if createErr != nil {
			return Result{}, createErr
		}
		users, err = z.listUsers(ctx)
		if err != nil {
			return Result{}, err
		}
		testHuman, ok = findUserByID(users, userID)
		if !ok {
			return Result{}, errors.New("created local test user is absent from ZITADEL readback")
		}
	} else {
		logf(cfg.Output, "local integration-test user already exists")
	}
	if testHuman.PreferredLoginName == "" || testHuman.UserID == "" || testHuman.Details.ResourceOwner == "" {
		return Result{}, errors.New("local test user readback is missing authoritative identity fields")
	}
	// AddHumanUser historically accepted multiple JSON spellings across the
	// v2 API transition. SetPassword is the authoritative write seam for the
	// credential used by the live integration test, and also repairs an
	// interrupted bootstrap whose persisted password no longer matches the
	// provider. The initializer is loopback-only and holds IAM owner rights.
	if err := z.setPassword(ctx, testHuman.UserID, password); err != nil {
		return Result{}, fmt.Errorf("set local ZITADEL test-user password: %w", err)
	}

	previousTOTP := ""
	if hasPrevious && previous.UserID == testHuman.UserID {
		previousTOTP = previous.TOTPSecret
	}
	totpSecret, err := z.ensureTOTP(ctx, testHuman.UserID, previousTOTP, cfg.Now)
	if err != nil {
		return Result{}, err
	}

	users, err = z.listUsers(ctx)
	if err != nil {
		return Result{}, err
	}
	machine, ok := findUser(users, "up-backend-sa")
	if !ok {
		logf(cfg.Output, "creating the local backend service account")
		machineID, createErr := z.createMachine(ctx)
		if createErr != nil {
			return Result{}, createErr
		}
		users, err = z.listUsers(ctx)
		if err != nil {
			return Result{}, err
		}
		var found bool
		machine, found = findUserByID(users, machineID)
		if !found {
			return Result{}, errors.New("created local service account is absent from ZITADEL readback")
		}
	} else {
		logf(cfg.Output, "local backend service account already exists")
	}
	if machine.UserID == "" {
		return Result{}, errors.New("local backend service account has no user id")
	}
	if machine.Details.ResourceOwner == "" || machine.Details.ResourceOwner != testHuman.Details.ResourceOwner {
		return Result{}, errors.New("local backend service account is outside the test user's organization")
	}

	// SessionService v2 requires session.write on the instance. ZITADEL's
	// dedicated, least-purpose manager role for a custom Login V2 client is
	// IAM_LOGIN_CLIENT; organization ownership alone does not grant it and is
	// surfaced by the provider as NotFound + AUTHZ-*.
	if err := z.ensureIAMLoginClient(ctx, machine.UserID); err != nil {
		return Result{}, err
	}
	// The dedicated runtime account needs no organization-level manager role.
	// Never rewrite or delete unexpected manual permissions: fail closed and
	// require an operator to inspect the local instance instead.
	if err := z.assertNoOrganizationMembership(ctx, testHuman.Details.ResourceOwner, machine.UserID); err != nil {
		return Result{}, err
	}
	if err := z.ensureServiceAccountKey(ctx, serviceKeyFile, machine.UserID); err != nil {
		return Result{}, err
	}
	projectID, err := z.ensureProject(ctx, testHuman.Details.ResourceOwner, cfg.ProjectName)
	if err != nil {
		return Result{}, err
	}
	if err := z.ensureProjectOwner(ctx, testHuman.Details.ResourceOwner, projectID, machine.UserID); err != nil {
		return Result{}, err
	}

	nextState := state{
		BaseURL:          strings.TrimSuffix(base.String(), "/"),
		KeyFile:          serviceKeyFile,
		User:             testHuman.PreferredLoginName,
		Password:         password,
		UserID:           testHuman.UserID,
		TOTPSecret:       totpSecret,
		OrganizationID:   testHuman.Details.ResourceOwner,
		ProjectID:        projectID,
		ServiceAccountID: machine.UserID,
	}
	if err := writeSecretJSON(stateFile, nextState, true); err != nil {
		return Result{}, fmt.Errorf("persist local ZITADEL state: %w", err)
	}
	logf(cfg.Output, "local ZITADEL bootstrap state updated")

	return Result{
		BaseURL:       nextState.BaseURL,
		StateFile:     stateFile,
		ServiceKey:    serviceKeyFile,
		UserLogin:     nextState.User,
		UserID:        nextState.UserID,
		Organization:  nextState.OrganizationID,
		ProjectID:     nextState.ProjectID,
		ServiceUserID: nextState.ServiceAccountID,
	}, nil
}

func withDefaults(cfg Config) Config {
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	if cfg.TestUser == "" {
		cfg.TestUser = defaultTestUser
	}
	if cfg.TestFirstName == "" {
		cfg.TestFirstName = "Zhixing"
	}
	if cfg.TestLastName == "" {
		cfg.TestLastName = "Lin"
	}
	if cfg.TestDisplay == "" {
		cfg.TestDisplay = "Zhixing Lin"
	}
	if cfg.ProjectName == "" {
		cfg.ProjectName = defaultProjectName
	}
	if cfg.ReadyTimeout <= 0 {
		cfg.ReadyTimeout = 5 * time.Minute
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = 2 * time.Second
	}
	if cfg.Output == nil {
		cfg.Output = io.Discard
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	return cfg
}

func validateLoopbackBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse local ZITADEL base URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("ZITADEL_BASE_URL must be a bare HTTP(S) loopback URL")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("ZITADEL_BASE_URL must be a bare HTTP(S) loopback URL")
		}
	}
	u.Path = ""
	return u, nil
}

func newLoopbackHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("validate local ZITADEL address: %w", err)
			}
			resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("resolve local ZITADEL address: %w", err)
			}
			if len(resolved) == 0 {
				return nil, errors.New("local ZITADEL address resolved to no IPs")
			}
			for _, candidate := range resolved {
				if !candidate.IP.IsLoopback() {
					return nil, errors.New("local ZITADEL address resolved outside loopback")
				}
			}
			return dialer.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2: true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("local ZITADEL redirects are not allowed")
		},
	}
}

func (c *client) endpoint(path string) string {
	copyURL := *c.base
	copyURL.Path = path
	return copyURL.String()
}

func (c *client) waitReady(ctx context.Context, timeout, interval time.Duration) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		req, err := http.NewRequestWithContext(deadlineCtx, http.MethodGet, c.endpoint("/debug/ready"), nil)
		if err != nil {
			return fmt.Errorf("build local ZITADEL readiness request: %w", err)
		}
		resp, requestErr := c.http.Do(req)
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}
		select {
		case <-deadlineCtx.Done():
			return errors.New("local ZITADEL did not become ready before the deadline")
		case <-time.After(interval):
		}
	}
}

func loadServiceAccountKey(path string) (serviceAccountKey, *rsa.PrivateKey, error) {
	if err := rejectSymlink(path); err != nil {
		return serviceAccountKey{}, nil, err
	}
	if err := restrictSecretFile(path); err != nil {
		return serviceAccountKey{}, nil, fmt.Errorf("restrict service-account key permissions: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return serviceAccountKey{}, nil, err
	}
	if len(raw) > maxResponseBytes {
		return serviceAccountKey{}, nil, errors.New("service-account key file is unexpectedly large")
	}
	return parseServiceAccountKey(raw)
}

func parseServiceAccountKey(raw []byte) (serviceAccountKey, *rsa.PrivateKey, error) {
	var key serviceAccountKey
	if err := json.Unmarshal(raw, &key); err != nil {
		return serviceAccountKey{}, nil, errors.New("service-account key file is malformed")
	}
	if key.KeyID == "" || key.UserID == "" || key.PrivateKeyPEM == "" {
		return serviceAccountKey{}, nil, errors.New("service-account key file is missing required fields")
	}
	block, _ := pem.Decode([]byte(key.PrivateKeyPEM))
	if block == nil {
		return serviceAccountKey{}, nil, errors.New("service-account private key is not PEM")
	}
	parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
	if parseErr == nil {
		privateKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return serviceAccountKey{}, nil, errors.New("service-account private key is not RSA")
		}
		return key, privateKey, nil
	}
	privateKey, parsePKCS1Err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if parsePKCS1Err != nil {
		return serviceAccountKey{}, nil, errors.New("service-account RSA private key is malformed")
	}
	return key, privateKey, nil
}

func signJWTAssertion(key serviceAccountKey, privateKey *rsa.PrivateKey, audience string, now time.Time, random io.Reader) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": key.KeyID, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": key.UserID,
		"sub": key.UserID,
		"aud": strings.TrimSuffix(audience, "/"),
		"iat": now.Add(-10 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(encoded))
	signature, err := rsa.SignPKCS1v15(random, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return encoded + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (c *client) exchangeJWT(ctx context.Context, assertion string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	form.Set("scope", "openid urn:zitadel:iam:org:project:id:zitadel:aud")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("/oauth/v2/token"), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.do(req, &response); err != nil {
		return "", err
	}
	if response.AccessToken == "" {
		return "", errors.New("ZITADEL token response is missing access_token")
	}
	return response.AccessToken, nil
}

type userRecord struct {
	UserID             string `json:"userId"`
	PreferredLoginName string `json:"preferredLoginName"`
	Details            struct {
		ResourceOwner string `json:"resourceOwner"`
	} `json:"details"`
}

func (c *client) listUsers(ctx context.Context) ([]userRecord, error) {
	var response struct {
		Result []userRecord `json:"result"`
	}
	if err := c.json(ctx, http.MethodPost, "/v2/users", "", map[string]any{}, &response); err != nil {
		return nil, fmt.Errorf("list local ZITADEL users: %w", err)
	}
	return response.Result, nil
}

func findUser(users []userRecord, shortName string) (userRecord, bool) {
	for _, user := range users {
		if user.PreferredLoginName == shortName || strings.HasPrefix(user.PreferredLoginName, shortName+"@") {
			return user, true
		}
	}
	return userRecord{}, false
}

func findUserByID(users []userRecord, id string) (userRecord, bool) {
	for _, user := range users {
		if user.UserID == id {
			return user, true
		}
	}
	return userRecord{}, false
}

func (c *client) createHuman(ctx context.Context, cfg Config, password string) (string, error) {
	body := map[string]any{
		"username": cfg.TestUser + "@zitadel.localhost",
		"profile": map[string]string{
			"givenName":   cfg.TestFirstName,
			"familyName":  cfg.TestLastName,
			"displayName": cfg.TestDisplay,
		},
		"email": map[string]any{
			"email":      cfg.TestUser + "@example.com",
			"isVerified": true,
		},
		"password": map[string]string{"password": password},
	}
	var response struct {
		UserID string `json:"userId"`
	}
	if err := c.json(ctx, http.MethodPost, "/v2/users/human", "", body, &response); err != nil {
		return "", fmt.Errorf("create local ZITADEL test user: %w", err)
	}
	if response.UserID == "" {
		return "", errors.New("ZITADEL create-human response is missing userId")
	}
	return response.UserID, nil
}

func (c *client) setPassword(ctx context.Context, userID, password string) error {
	body := map[string]any{
		"newPassword": map[string]any{
			"password":       password,
			"changeRequired": false,
		},
	}
	return c.json(ctx, http.MethodPost, "/v2/users/"+url.PathEscape(userID)+"/password", "", body, nil)
}

func (c *client) ensureTOTP(ctx context.Context, userID, previousSecret string, now func() time.Time) (string, error) {
	secret, err := c.registerTOTP(ctx, userID)
	if err == nil {
		if err := c.verifyTOTP(ctx, userID, secret, now()); err != nil {
			return "", err
		}
		return secret, nil
	}
	var statusErr *httpStatusError
	if !errors.As(err, &statusErr) || statusErr.Status != http.StatusConflict {
		return "", fmt.Errorf("register local ZITADEL TOTP: %w", err)
	}
	if previousSecret != "" {
		if _, codeErr := totpCode(previousSecret, now()); codeErr != nil {
			return "", errors.New("stored local ZITADEL TOTP secret is malformed")
		}
		return previousSecret, nil
	}
	if err := c.json(ctx, http.MethodDelete, "/v2/users/"+url.PathEscape(userID)+"/totp", "", nil, nil); err != nil {
		return "", fmt.Errorf("remove unrecoverable local ZITADEL TOTP: %w", err)
	}
	secret, err = c.registerTOTP(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("re-register local ZITADEL TOTP: %w", err)
	}
	if err := c.verifyTOTP(ctx, userID, secret, now()); err != nil {
		return "", err
	}
	return secret, nil
}

func (c *client) registerTOTP(ctx context.Context, userID string) (string, error) {
	var response struct {
		Secret string `json:"secret"`
	}
	if err := c.json(ctx, http.MethodPost, "/v2/users/"+url.PathEscape(userID)+"/totp", "", map[string]any{}, &response); err != nil {
		return "", err
	}
	if response.Secret == "" {
		return "", errors.New("ZITADEL TOTP response is missing secret")
	}
	if _, err := totpCode(response.Secret, time.Now()); err != nil {
		return "", errors.New("ZITADEL returned a malformed TOTP secret")
	}
	return response.Secret, nil
}

func (c *client) verifyTOTP(ctx context.Context, userID, secret string, now time.Time) error {
	code, err := totpCode(secret, now)
	if err != nil {
		return errors.New("local ZITADEL TOTP secret is malformed")
	}
	if err := c.json(ctx, http.MethodPost, "/v2/users/"+url.PathEscape(userID)+"/totp/verify", "", map[string]string{"code": code}, nil); err != nil {
		return fmt.Errorf("verify local ZITADEL TOTP: %w", err)
	}
	return nil
}

func totpCode(secret string, now time.Time) (string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(secret))
	if remainder := len(normalized) % 8; remainder != 0 {
		normalized += strings.Repeat("=", 8-remainder)
	}
	key, err := base32.StdEncoding.DecodeString(normalized)
	if err != nil || len(key) == 0 {
		return "", errors.New("invalid base32 TOTP secret")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000), nil
}

func (c *client) createMachine(ctx context.Context) (string, error) {
	body := map[string]string{
		"userName":    "up-backend-sa@zitadel.localhost",
		"name":        "United Pass backend",
		"description": "United Pass backend API service account",
	}
	var response struct {
		UserID string `json:"userId"`
	}
	if err := c.json(ctx, http.MethodPost, "/management/v1/users/machine", "", body, &response); err != nil {
		return "", fmt.Errorf("create local ZITADEL service account: %w", err)
	}
	if response.UserID == "" {
		return "", errors.New("ZITADEL create-machine response is missing userId")
	}
	return response.UserID, nil
}

func (c *client) assertNoOrganizationMembership(ctx context.Context, orgID, userID string) error {
	members, err := c.searchMembers(ctx, "/management/v1/orgs/me/members/_search", orgID)
	if err != nil {
		return fmt.Errorf("search local ZITADEL organization members: %w", err)
	}
	if _, exists := memberRoles(members, userID); exists {
		return errors.New("local ZITADEL backend service account has unexpected organization roles; refusing to modify them")
	}
	return nil
}

func (c *client) ensureIAMLoginClient(ctx context.Context, userID string) error {
	members, err := c.searchMembers(ctx, "/admin/v1/members/_search", "")
	if err != nil {
		return fmt.Errorf("search local ZITADEL instance members: %w", err)
	}
	exists, err := exactMemberRole(members, userID, "IAM_LOGIN_CLIENT")
	if err != nil {
		return errors.New("local ZITADEL backend service account must have exactly IAM_LOGIN_CLIENT; refusing to modify unexpected instance roles")
	}
	if exists {
		return nil
	}
	body := map[string]any{"userId": userID, "roles": []string{"IAM_LOGIN_CLIENT"}}
	if err := c.json(ctx, http.MethodPost, "/admin/v1/members", "", body, nil); err != nil {
		return fmt.Errorf("authorize local ZITADEL service account as login client: %w", err)
	}
	return nil
}

func (c *client) ensureServiceAccountKey(ctx context.Context, path, expectedUserID string) error {
	if _, err := os.Lstat(path); err == nil {
		key, _, loadErr := loadServiceAccountKey(path)
		if loadErr != nil {
			return fmt.Errorf("validate existing local service-account key: %w", loadErr)
		}
		if key.UserID != expectedUserID {
			return errors.New("existing local service-account key belongs to a different user")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect local service-account key: %w", err)
	}

	var response struct {
		KeyDetails string `json:"keyDetails"`
	}
	endpoint := "/management/v1/users/" + url.PathEscape(expectedUserID) + "/keys"
	if err := c.json(ctx, http.MethodPost, endpoint, "", map[string]int{"type": 1}, &response); err != nil {
		return fmt.Errorf("create local ZITADEL service-account key: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(response.KeyDetails)
	if err != nil || len(raw) == 0 || len(raw) > maxResponseBytes {
		return errors.New("ZITADEL service-account key response is malformed")
	}
	key, _, err := parseServiceAccountKey(raw)
	if err != nil || key.UserID != expectedUserID {
		return errors.New("ZITADEL service-account key response has an invalid key shape")
	}
	if err := writeSecretBytes(path, raw, false); err != nil {
		return fmt.Errorf("write local ZITADEL service-account key: %w", err)
	}
	return nil
}

type projectRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *client) ensureProject(ctx context.Context, orgID, name string) (string, error) {
	var search struct {
		Result []projectRecord `json:"result"`
	}
	if err := c.json(ctx, http.MethodPost, "/management/v1/projects/_search", orgID, map[string]any{}, &search); err != nil {
		return "", fmt.Errorf("search local ZITADEL projects: %w", err)
	}
	for _, project := range search.Result {
		if project.Name == name && project.ID != "" {
			return project.ID, nil
		}
	}
	var created struct {
		ID string `json:"id"`
	}
	body := map[string]any{
		"name":                 name,
		"projectRoleAssertion": false,
		"projectRoleCheck":     false,
		"hasProjectCheck":      false,
	}
	if err := c.json(ctx, http.MethodPost, "/management/v1/projects", orgID, body, &created); err != nil {
		return "", fmt.Errorf("create local ZITADEL provisioning project: %w", err)
	}
	if created.ID == "" {
		return "", errors.New("ZITADEL create-project response is missing id")
	}
	return created.ID, nil
}

type memberRecord struct {
	UserID string   `json:"userId"`
	Roles  []string `json:"roles"`
}

func (c *client) searchMembers(ctx context.Context, path, orgID string) ([]memberRecord, error) {
	var response struct {
		Result []memberRecord `json:"result"`
	}
	if err := c.json(ctx, http.MethodPost, path, orgID, map[string]any{}, &response); err != nil {
		return nil, err
	}
	return response.Result, nil
}

func memberRoles(members []memberRecord, userID string) ([]string, bool) {
	for _, member := range members {
		if member.UserID == userID {
			return append([]string(nil), member.Roles...), true
		}
	}
	return nil, false
}

func exactMemberRole(members []memberRecord, userID, role string) (bool, error) {
	var matched []memberRecord
	for _, member := range members {
		if member.UserID == userID {
			matched = append(matched, member)
		}
	}
	if len(matched) == 0 {
		return false, nil
	}
	if len(matched) != 1 || len(matched[0].Roles) != 1 || matched[0].Roles[0] != role {
		return true, errors.New("membership roles differ from the required exact role")
	}
	return true, nil
}

func (c *client) ensureProjectOwner(ctx context.Context, orgID, projectID, userID string) error {
	basePath := "/management/v1/projects/" + url.PathEscape(projectID) + "/members"
	members, err := c.searchMembers(ctx, basePath+"/_search", orgID)
	if err != nil {
		return fmt.Errorf("search local ZITADEL project members: %w", err)
	}
	exists, err := exactMemberRole(members, userID, "PROJECT_OWNER")
	if err != nil {
		return errors.New("local ZITADEL backend service account must have exactly PROJECT_OWNER on the provisioning project; refusing to modify unexpected project roles")
	}
	if exists {
		return nil
	}
	body := map[string]any{"userId": userID, "roles": []string{"PROJECT_OWNER"}}
	if err := c.json(ctx, http.MethodPost, basePath, orgID, body, nil); err != nil {
		return fmt.Errorf("authorize local ZITADEL service account on project: %w", err)
	}
	return nil
}

func (c *client) json(ctx context.Context, method, path, orgID string, body, output any) error {
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode ZITADEL request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), requestBody)
	if err != nil {
		return fmt.Errorf("build ZITADEL request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if orgID != "" {
		req.Header.Set("X-Zitadel-Orgid", orgID)
	}
	return c.do(req, output)
}

func (c *client) do(req *http.Request, output any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("local ZITADEL request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return &httpStatusError{Method: req.Method, Path: req.URL.Path, Status: resp.StatusCode}
	}
	if output == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if err := decoder.Decode(output); err != nil {
		return errors.New("local ZITADEL response is malformed")
	}
	return nil
}

func readState(path string) (state, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state{}, false, nil
	}
	if err != nil {
		return state{}, false, fmt.Errorf("inspect local ZITADEL state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return state{}, false, errors.New("local ZITADEL state must be a regular file")
	}
	if err := restrictSecretFile(path); err != nil {
		return state{}, false, fmt.Errorf("restrict local ZITADEL state permissions: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return state{}, false, fmt.Errorf("read local ZITADEL state: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return state{}, false, errors.New("local ZITADEL state is unexpectedly large")
	}
	var value state
	if err := json.Unmarshal(raw, &value); err != nil {
		return state{}, false, errors.New("local ZITADEL state is malformed")
	}
	if value.Password != "" {
		if err := validatePassword(value.Password); err != nil {
			return state{}, false, errors.New("stored local ZITADEL password is malformed")
		}
	}
	return value, true, nil
}

func writeSecretJSON(path string, value any, replace bool) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writeSecretBytes(path, encoded, replace)
}

func writeSecretBytes(path string, value []byte, replace bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := rejectSymlink(filepath.Dir(path)); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".zitadel-secret-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		_ = temp.Close()
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if err := restrictSecretFile(tempPath); err != nil {
		return err
	}
	if _, err := temp.Write(value); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if existing, statErr := os.Lstat(path); statErr == nil {
		if existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
			return errors.New("refusing to overwrite a non-regular local secret file")
		}
		if !replace {
			return os.ErrExist
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	removeTemp = false
	return restrictSecretFile(path)
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("local ZITADEL path must not be a symbolic link: %s", path)
	}
	return nil
}

func generatePassword(random io.Reader) (string, error) {
	value := make([]byte, 30)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", fmt.Errorf("generate local ZITADEL test password: %w", err)
	}
	return "Aa1!" + hex.EncodeToString(value), nil
}

func validatePassword(value string) error {
	if len(value) < 16 || len(value) > 72 || !strings.ContainsAny(value, "abcdefghijklmnopqrstuvwxyz") ||
		!strings.ContainsAny(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || !strings.ContainsAny(value, "0123456789") {
		return errors.New("local ZITADEL test password does not satisfy the complexity policy")
	}
	for _, character := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", character) {
			return nil
		}
	}
	return errors.New("local ZITADEL test password does not satisfy the complexity policy")
}

func logf(output io.Writer, message string) {
	_, _ = fmt.Fprintf(output, "[zitadel-bootstrap] %s\n", message)
}
