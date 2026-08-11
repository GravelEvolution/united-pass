//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 7 audit search and durable export contracts
//

package audit

import (
	"context"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type ExportID string

var (
	ErrNotFound   = errors.New("audit resource not found")
	ErrValidation = errors.New("audit query validation failed")
	ErrNotReady   = errors.New("audit export not ready")
	ErrExpired    = errors.New("audit export expired")
)

type Event struct {
	EventID     string    `json:"eventId"`
	EventType   string    `json:"eventType"`
	ActorName   string    `json:"actorName"`
	ActorID     string    `json:"actorId"`
	TargetLabel string    `json:"targetLabel"`
	TargetID    string    `json:"targetId"`
	OccurredAt  time.Time `json:"occurredAt"`
	Result      string    `json:"result"`
	RequestID   string    `json:"requestId"`
	Details     string    `json:"details"`
}

type Query struct {
	Cursor    string     `json:"cursor,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Query     string     `json:"query,omitempty"`
	EventType string     `json:"eventType,omitempty"`
	Result    string     `json:"result,omitempty"`
	ActorName string     `json:"actorName,omitempty"`
	RequestID string     `json:"requestId,omitempty"`
	From      *time.Time `json:"from,omitempty"`
	To        *time.Time `json:"to,omitempty"`
}

type Page struct {
	Items      []Event
	NextCursor string
	HasMore    bool
}

type Export struct {
	ExportID    ExportID        `json:"exportId"`
	Status      string          `json:"status"`
	DownloadURL *string         `json:"downloadUrl"`
	RequestedAt time.Time       `json:"requestedAt"`
	CompletedAt *time.Time      `json:"completedAt"`
	TotalEvents int             `json:"totalEvents"`
	ExpiresAt   *time.Time      `json:"-"`
	ActorID     identity.UserID `json:"-"`
	Query       Query           `json:"-"`
	Content     []byte          `json:"-"`
}

type Repository interface {
	List(context.Context, Query) (Page, error)
	ListForExport(context.Context, Query, int) ([]Event, error)
	CreateExport(context.Context, identity.UserID, string, Query) (Export, error)
	GetExport(context.Context, ExportID) (Export, error)
	ClaimExports(context.Context, int) ([]Export, error)
	CompleteExport(context.Context, ExportID, []byte, int, time.Time) error
	FailExport(context.Context, ExportID, string) error
	RecordAuthorizationDenied(context.Context, identity.UserID, string, string) error
}
