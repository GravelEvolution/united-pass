package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/cerbos"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/postgres"
	"github.com/GravelEvolution/united-pass/backend/internal/adminpolicybootstrap"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

const commandTimeout = 5 * time.Minute

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run reconciles only the reviewed fixed administrator policy catalog. It is
// intentionally separate from admin-bootstrap so a policy-only release does
// not need provider credentials, challenge material, or a user-role mutation.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("admin-policy-reconcile", flag.ContinueOnError)
	flags.SetOutput(stderr)
	actorUserID := flags.String("actor-user-id", "", "existing United Pass administrator user ID used for audit attribution")
	requestID := flags.String("request-id", "", "unique reconciliation request ID")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if strings.TrimSpace(*actorUserID) == "" || strings.TrimSpace(*requestID) == "" {
		fmt.Fprintln(stderr, "status=failed error=invalid_arguments")
		return 2
	}

	if _, err := config.LoadDotEnv(".env"); err != nil {
		fmt.Fprintln(stderr, "status=failed error=configuration")
		return 1
	}
	cfg, err := config.Load()
	if err != nil || !cfg.HasDatabase() || !cfg.Cerbos.Configured() {
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

	cerbosClient, err := cerbos.NewClient(
		cfg.Cerbos.PDPURL,
		cfg.Cerbos.AdminURL,
		cfg.Cerbos.AdminUsername,
		cfg.Cerbos.AdminPassword,
		&http.Client{Timeout: cfg.Cerbos.RequestTimeout},
	)
	if err != nil {
		fmt.Fprintln(stderr, "status=failed error=policy_configuration")
		return 1
	}
	service := adminpolicybootstrap.NewService(postgres.NewPolicyRepository(pool.PgxPool()), cerbosClient, cerbosClient)
	if err := service.Ensure(ctx, identity.UserID(strings.TrimSpace(*actorUserID)), strings.TrimSpace(*requestID)); err != nil {
		fmt.Fprintln(stderr, "status=failed error=policy_reconciliation")
		return 1
	}

	fmt.Fprintln(stdout, "status=ready")
	return 0
}
