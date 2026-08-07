//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Identity domain types (user, user ID, user status)
//

// Package identity defines the core user identity domain types for United Pass.
// These types are independent of any infrastructure concern (HTTP, SQL, Redis).
package identity

import (
	"errors"
	"time"
)

// UserID is the stable United Pass user identifier. It is generated and
// controlled by United Pass, never derived from an email, phone, or provider
// subject.
type UserID string

// UserStatus represents the lifecycle state of a user account.
type UserStatus string

const (
	UserStatusPending  UserStatus = "pending"
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
)

// Persona represents a user persona type. An employee is not a separate
// account — the identity model is one User with an optional employee profile.
type Persona string

const (
	PersonaConsumer Persona = "consumer"
	PersonaEmployee Persona = "employee"
)

// User is the core user entity. It does not contain passwords, MFA secrets, or
// provider tokens.
type User struct {
	ID            UserID
	Status        UserStatus
	DisplayName   string
	Nickname      string
	AvatarURL     string
	Email         string
	EmailVerified bool
	Phone         string
	PhoneVerified bool
	Personas      []Persona
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Version       int
}

// IdentityLink binds an external provider identity to a stable United Pass
// user. The same provider subject cannot be linked to multiple users.
type IdentityLink struct {
	ID               string
	UserID           UserID
	Provider         string
	ProviderTenantID string
	ProviderSubject  string
	CreatedAt        time.Time
	LastSeenAt       time.Time
}

// ErrUserNotFound is returned when a user lookup yields no result.
var ErrUserNotFound = errors.New("user not found")

// ErrIdentityLinkConflict is returned when a provider subject is already
// linked to a different United Pass user.
var ErrIdentityLinkConflict = errors.New("identity link conflict")

// IsValid reports whether the UserStatus is a recognized value.
func (s UserStatus) IsValid() bool {
	switch s {
	case UserStatusPending, UserStatusActive, UserStatusDisabled:
		return true
	}
	return false
}

// CanAuthenticate reports whether a user in this status is permitted to
// establish a new session.
func (s UserStatus) CanAuthenticate() bool {
	return s == UserStatusActive
}

// MaskPhone returns a masked representation of a phone number for API
// responses. It masks all but the last 4 digits. If the number is too short
// to mask safely, it returns a fully masked placeholder.
func MaskPhone(phone string) string {
	if len(phone) <= 4 {
		return "****"
	}
	masked := make([]byte, len(phone))
	for i := range masked {
		if i < len(phone)-4 {
			masked[i] = '*'
		} else {
			masked[i] = phone[i]
		}
	}
	return string(masked)
}
