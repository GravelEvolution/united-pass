package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/cerbos"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/postgres"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/zitadel"
	"github.com/GravelEvolution/united-pass/backend/internal/adminbootstrap"
	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminpolicybootstrap"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

const commandTimeout = 5 * time.Minute

type challengeDocument struct {
	Question string `json:"question"`
	Answer   string `json:"answer"`
}
type approvalDocument struct {
	Approvals []adminbootstrap.Approval `json:"approvals"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("admin-bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	userID := flags.String("target-user-id", "", "exact United Pass user ID")
	tenant := flags.String("provider-tenant-id", "", "exact provider tenant ID")
	subject := flags.String("provider-subject", "", "exact provider subject")
	sourceVersion := flags.String("source-version", "", "authoritative DreamUP source version")
	keyringPath := flags.String("operator-keyring", "", "owner-only operator public-key ring")
	approvalPath := flags.String("approval-file", "", "owner-only approval document")
	challengePath := flags.String("challenge-file", "", "owner-only challenge document")
	verifyOnly := flags.Bool("verify-only", false, "read back exact state without mutation")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *userID == "" || *tenant == "" || *subject == "" || *sourceVersion == "" {
		fmt.Fprintln(stderr, "status=failed error=invalid_arguments")
		return 2
	}
	if _, err := config.LoadDotEnv(".env"); err != nil {
		fmt.Fprintln(stderr, "status=failed error=configuration")
		return 1
	}
	cfg, err := config.Load()
	if err != nil || !cfg.HasDatabase() || !cfg.HasAuthProvider() || !cfg.DreamUPAdmin.Enabled {
		fmt.Fprintln(stderr, "status=failed error=configuration")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	pool, err := postgres.NewPool(ctx, cfg)
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=database")
		return 1
	}
	defer pool.Close()
	if !cfg.Cerbos.Configured() {
		fmt.Fprintln(stderr, "status=failed error=policy_configuration")
		return 1
	}
	cerbosClient, err := cerbos.NewClient(cfg.Cerbos.PDPURL, cfg.Cerbos.AdminURL, cfg.Cerbos.AdminUsername, cfg.Cerbos.AdminPassword, &http.Client{Timeout: cfg.Cerbos.RequestTimeout})
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=policy_configuration")
		return 1
	}
	policyService := adminpolicybootstrap.NewService(postgres.NewPolicyRepository(pool.PgxPool()), cerbosClient, cerbosClient)
	if err := policyService.Ensure(ctx, identity.UserID(*userID), "admin-bootstrap-policy-"+*sourceVersion); err != nil {
		fmt.Fprintln(stderr, "status=failed error=policy_bootstrap")
		return 1
	}
	codec, err := adminpagination.NewCursorCodec(cfg.Session.EncryptionKey, nil)
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=configuration")
		return 1
	}
	sdk, err := zitadel.NewSDKClient(ctx, cfg.Auth)
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=provider")
		return 1
	}
	defer sdk.Close()
	challengeKeys, err := adminstepup.LoadKeyring(cfg.DreamUPAdmin.ChallengeEncryptionKeyringPath, cfg.DreamUPAdmin.ChallengeEncryptionCurrentKeyID)
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=keyring")
		return 1
	}
	pepperKeys, err := adminstepup.LoadKeyring(cfg.DreamUPAdmin.ChallengePepperKeyringPath, cfg.DreamUPAdmin.ChallengePepperCurrentKeyID)
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=keyring")
		return 1
	}
	cipher, err := adminstepup.NewAESGCMCipher(challengeKeys)
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=keyring")
		return 1
	}
	hasher, err := adminstepup.NewAnswerHasher(pepperKeys, adminstepup.DefaultArgon2Params, cfg.DreamUPAdmin.Argon2MaxConcurrent)
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=keyring")
		return 1
	}
	operatorKeys, err := adminbootstrap.LoadApprovalKeyring(*keyringPath)
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=operator_keyring")
		return 1
	}
	service, err := adminbootstrap.NewService(adminbootstrap.Dependencies{Local: postgres.NewAdminLocalIdentityReadback(pool.PgxPool()), Provider: zitadel.NewAdminIdentityReadback(sdk.UserServiceV2(), *tenant), Repository: postgres.NewAdminBootstrapRepository(pool.PgxPool(), codec), Hasher: hasher, Cipher: cipher, Approvals: operatorKeys})
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=bootstrap")
		return 1
	}
	change := adminbootstrap.Change{Action: adminbootstrap.GrantSuper, TargetUserID: identity.UserID(*userID), ExpectedUsername: adminbootstrap.ExpectedLoginName, Provider: zitadel.ProviderName, ProviderTenantID: *tenant, ProviderSubject: *subject, Event: adminroles.RegisteredEvent{EventID: adminbootstrap.ShanghaiEventID, Series: "dreamup", Slug: "dreamup-shanghai-2026", DisplayName: "MoonStone DreamUP 上海站 2026", SourceVersion: *sourceVersion, AuthoritativeReadAt: time.Now().UTC()}}
	var result adminbootstrap.Result
	if *verifyOnly {
		result, err = service.Readback(ctx, change)
	} else {
		var approvals approvalDocument
		var challenge challengeDocument
		if readSecureJSON(*approvalPath, &approvals) != nil || len(approvals.Approvals) != 2 || readSecureJSON(*challengePath, &challenge) != nil {
			fmt.Fprintln(stderr, "status=failed error=secure_input")
			return 1
		}
		result, err = service.Bootstrap(ctx, adminbootstrap.Input{Change: change, Approvals: approvals.Approvals, Question: challenge.Question, Answer: challenge.Answer})
		challenge.Question = ""
		challenge.Answer = ""
	}
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=bootstrap")
		return 1
	}
	fmt.Fprintf(stdout, "status=%s username=%s user_id=%s binding_id=%s event_id=%s must_rotate=%t\n", result.Status, result.Username, result.UserID, result.BindingID, result.EventID, result.MustRotate)
	return 0
}

func readSecureJSON(path string, destination any) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("secure input requires absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return errors.New("insecure input")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return errors.New("unavailable input")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid input")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid input")
	}
	return nil
}
