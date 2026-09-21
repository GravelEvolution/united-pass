package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/cerbos"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/postgres"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

func main() {
	userID := identity.UserID(os.Args[1])
	cfg, err := config.Load()
	if err != nil {
		fmt.Println("config:", err)
		return
	}
	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, cfg)
	if err != nil {
		fmt.Println("pool:", err)
		return
	}
	defer pool.Close()

	cerbosClient, err := cerbos.NewClient(cfg.Cerbos.PDPURL, cfg.Cerbos.AdminURL, cfg.Cerbos.AdminUsername, cfg.Cerbos.AdminPassword, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		fmt.Println("cerbos client:", err)
		return
	}

	roles := postgres.NewAdminRoleRepository(pool.PgxPool(), nil)
	principal := postgres.NewPermissionContextRepository(pool.PgxPool())
	policies := postgres.NewPolicyRepository(pool.PgxPool())
	authz := permissions.NewCerbosAuthorizer(roles, principal, policies, cerbosClient)

	// 打印 principal
	pc, err := principal.GetPermissionPrincipal(ctx, userID)
	if err != nil {
		fmt.Println("principal err:", err)
		return
	}
	fmt.Printf("principal.Attributes: %v\n", pc.Attributes)
	fmt.Printf("principal.Roles: %v challengeVersion=%d\n", pc.Roles, pc.ChallengeVersion)

	action := permissions.ActionApplicationReadBasic
	resource := permissions.Resource{Kind: "event", ID: "evt_dreamup_shanghai_2026", EventID: "evt_dreamup_shanghai_2026"}

	decision, err := authz.Check(ctx, userID, action, resource)
	if err != nil {
		fmt.Println("check err:", err)
		return
	}
	fmt.Printf("DECISION: Allowed=%v Role=%q BindingID=%q BindingVersion=%d ChallengeVersion=%d\n",
		decision.Allowed, decision.Role, decision.BindingID, decision.BindingVersion, decision.ChallengeVersion)
}
