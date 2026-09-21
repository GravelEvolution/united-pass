package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/adminbootstrap"
	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type AdminBootstrapRepository struct {
	uow        *AdminUnitOfWork
	roles      *AdminRoleRepository
	challenges *AdminStepUpRepository
	events     *DreamUPEventRegistryRepository
}

func NewAdminBootstrapRepository(pool *pgxpool.Pool, codec *adminpagination.CursorCodec) *AdminBootstrapRepository {
	return &AdminBootstrapRepository{uow: NewAdminUnitOfWork(pool, codec), roles: NewAdminRoleRepository(pool, codec), challenges: NewAdminStepUpRepository(pool), events: NewDreamUPEventRegistryRepository(pool, codec)}
}

func (r *AdminBootstrapRepository) Apply(ctx context.Context, mutation adminbootstrap.Mutation) (adminbootstrap.BootstrapState, error) {
	if r == nil || r.uow == nil || len(mutation.Approvals) != 2 || mutation.RequestHash == "" {
		return adminbootstrap.BootstrapState{}, adminbootstrap.ErrInvalidApproval
	}
	err := r.uow.Within(ctx, func(repos adminstore.Repositories) error {
		for _, approval := range mutation.Approvals {
			if err := repos.OperatorApprovals.Create(ctx, adminstore.OperatorApproval{ID: approval.ID, RequestHash: approval.RequestHash, OperatorID: approval.OperatorUserID, KeyID: approval.KeyID, Signature: approval.Signature, ExpiresAt: approval.ExpiresAt, CreatedAt: approval.CreatedAt}); err != nil {
				return adminbootstrap.ErrApprovalReplay
			}
		}
		audit := adminroles.MutationAudit{ActorID: identity.UserID(mutation.Approvals[0].OperatorUserID), ReasonID: mutation.State.Binding.ReasonID, RequestID: "admin-bootstrap-" + mutation.RequestHash[:32], Action: "admin.bootstrap.grant_super"}
		if _, err := repos.EventRegistry.PutExact(ctx, mutation.State.Event, audit); err != nil {
			return err
		}
		if _, err := repos.Roles.Create(ctx, mutation.State.Binding, audit); err != nil {
			return err
		}
		if _, err := repos.Challenges.PutCredential(ctx, mutation.Credential, 0); err != nil {
			return err
		}
		if err := repos.SecurityEvents.Record(ctx, applications.SecurityEvent{EventID: applications.NewSecurityEventID(), EventType: "admin.challenge.enrolled", ActorUserID: audit.ActorID, RequestID: audit.RequestID, Operation: audit.Action, Result: applications.SecurityEventSuccess, TargetKey: "user_id", TargetID: string(mutation.State.Binding.UserID), OccurredAt: time.Now().UTC()}); err != nil {
			return err
		}
		return repos.OperatorApprovals.MarkTerminal(ctx, mutation.RequestHash, time.Now().UTC())
	})
	if err != nil {
		return adminbootstrap.BootstrapState{}, err
	}
	return r.Readback(ctx, mutation.State.Binding.UserID, mutation.State.Event.EventID)
}

func (r *AdminBootstrapRepository) Readback(ctx context.Context, userID identity.UserID, eventID string) (adminbootstrap.BootstrapState, error) {
	if r == nil || r.roles == nil || r.challenges == nil || r.events == nil {
		return adminbootstrap.BootstrapState{}, errors.New("postgres: bootstrap repository unavailable")
	}
	binding, err := r.roles.GetForScope(ctx, userID, adminroles.Scope{Kind: adminroles.ScopeSystem})
	if err != nil {
		return adminbootstrap.BootstrapState{}, fmt.Errorf("postgres: bootstrap role readback: %w", err)
	}
	challenge, err := r.challenges.Get(ctx, userID)
	if err != nil {
		return adminbootstrap.BootstrapState{}, fmt.Errorf("postgres: bootstrap challenge readback: %w", err)
	}
	event, err := r.events.GetExact(ctx, eventID)
	if err != nil {
		return adminbootstrap.BootstrapState{}, fmt.Errorf("postgres: bootstrap event readback: %w", err)
	}
	return adminbootstrap.BootstrapState{Binding: binding, Challenge: challenge, Event: event}, nil
}

var _ adminbootstrap.Repository = (*AdminBootstrapRepository)(nil)
