package dreamupadmin

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
)

const (
	ReviewIdentityProtectedReason = "报名审核查看参赛者个人信息"
	reviewIdentityReasonVersion   = int64(1)
	reviewIdentityReasonSchema    = "dreamup-review-identity-reason/v1"
)

type reviewIdentityProtectedReasonPayload struct {
	Schema             string `json:"schema"`
	Reason             string `json:"reason"`
	Action             string `json:"action"`
	EventID            string `json:"eventId"`
	TargetType         string `json:"targetType"`
	TargetID           string `json:"targetId"`
	RequestFingerprint string `json:"requestFingerprint"`
}

func ReviewIdentityProtectedReasonID(requestID string) string {
	return "review_identity_" + requestID
}

func (s *Service) persistReviewIdentityReason(ctx context.Context, actor Actor, input ProxyRequest) error {
	reasonID, protectedPayload, err := validateReviewIdentityReasonRequest(actor, input)
	if err != nil {
		return err
	}
	if s.reasonUOW == nil || s.reasonCipher == nil {
		return ErrUpstream
	}
	sealed, err := s.reasonCipher.Encrypt(
		adminstepup.PurposeProtectedReason,
		string(actor.UserID),
		reasonID,
		reviewIdentityReasonVersion,
		protectedPayload,
	)
	if err != nil {
		return ErrUpstream
	}
	incoming := adminstore.ProtectedReason{
		ID: reasonID, OwnerUserID: string(actor.UserID), OperationKind: "direct_read",
		KeyID: sealed.KeyID, Nonce: sealed.Nonce, Ciphertext: sealed.Ciphertext,
		CreatedAt: s.now().UTC(),
	}
	err = s.reasonUOW.Within(ctx, func(repositories adminstore.Repositories) error {
		if repositories.Reasons == nil {
			return errors.New("dreamupadmin: protected reason repository unavailable")
		}
		stored, _, createErr := repositories.Reasons.CreateOrReplay(ctx, incoming)
		if createErr != nil {
			return createErr
		}
		if verifyErr := s.verifyReviewIdentityReason(stored, actor, reasonID, protectedPayload); verifyErr != nil {
			return verifyErr
		}
		if stored.TerminalAt != nil {
			return nil
		}
		terminal := s.now().UTC()
		return repositories.Reasons.MarkTerminal(ctx, stored.ID, terminal, terminal.AddDate(2, 0, 0))
	})
	if err != nil {
		return ErrUpstream
	}
	return nil
}

func (s *Service) verifyReviewIdentityReason(stored adminstore.ProtectedReason, actor Actor, reasonID, protectedPayload string) error {
	if stored.ID != reasonID || stored.OwnerUserID != string(actor.UserID) || stored.OperationKind != "direct_read" ||
		stored.KeyID == "" || len(stored.Nonce) == 0 || len(stored.Ciphertext) == 0 || stored.CreatedAt.IsZero() || stored.PurgedAt != nil {
		return adminstore.ErrIdempotencyConflict
	}
	plaintext, err := s.reasonCipher.Decrypt(
		adminstepup.PurposeProtectedReason,
		stored.OwnerUserID,
		stored.ID,
		reviewIdentityReasonVersion,
		adminstepup.EncryptedValue{KeyID: stored.KeyID, Nonce: stored.Nonce, Ciphertext: stored.Ciphertext},
	)
	if err != nil || plaintext != protectedPayload {
		return adminstore.ErrIdempotencyConflict
	}
	if stored.TerminalAt == nil && stored.ConsumedAt == nil && stored.ExpiresAt == nil {
		return nil
	}
	if stored.TerminalAt == nil || stored.ConsumedAt == nil || stored.ExpiresAt == nil ||
		!stored.ConsumedAt.Equal(*stored.TerminalAt) || !stored.ExpiresAt.Equal(stored.TerminalAt.AddDate(2, 0, 0)) {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

func validateReviewIdentityReasonRequest(actor Actor, input ProxyRequest) (string, string, error) {
	expectation, err := expectedMutationReceipt(input)
	if err != nil || expectation.Action != "identity.read_restricted" || len(input.Query) != 0 {
		return "", "", ErrInvalidRequest
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(input.Body, &object); err != nil || len(object) != 1 || object["protectedReasonId"] == nil {
		return "", "", ErrInvalidRequest
	}
	var reasonID string
	if json.Unmarshal(object["protectedReasonId"], &reasonID) != nil {
		return "", "", ErrInvalidRequest
	}
	expectedID := ReviewIdentityProtectedReasonID(input.RequestID)
	if reasonID != expectedID {
		return "", "", ErrInvalidRequest
	}
	canonicalRequest, err := json.Marshal([10]string{
		reviewIdentityReasonSchema,
		string(actor.UserID),
		input.EventID,
		string(input.Capability),
		input.ResourceKind,
		input.ResourceID,
		input.Method,
		input.Path,
		input.IdempotencyKey,
		input.IfMatch,
	})
	if err != nil {
		return "", "", ErrInvalidRequest
	}
	payload, err := json.Marshal(reviewIdentityProtectedReasonPayload{
		Schema:             reviewIdentityReasonSchema,
		Reason:             ReviewIdentityProtectedReason,
		Action:             expectation.Action,
		EventID:            input.EventID,
		TargetType:         expectation.TargetType,
		TargetID:           expectation.TargetID,
		RequestFingerprint: sha256Hex(canonicalRequest),
	})
	if err != nil {
		return "", "", ErrInvalidRequest
	}
	return expectedID, string(payload), nil
}
