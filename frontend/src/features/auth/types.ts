//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Authentication feature contract types
//

export type MfaChallengeState =
  | "password_required"
  | "totp_required"
  | "passkey_available"
  | "recovery_required"
  | "challenge_expired"
  | "too_many_attempts";

export type MfaMethod = "totp" | "passkey" | "recovery_code";

export type LoginResult =
  | { status: "success"; redirectUrl: string }
  | { status: "mfa_required"; mfaToken: string; availableMethods: MfaMethod[] }
  | { status: "rate_limited"; retryAfter: number }
  | { status: "invalid_credentials" };

export type PasswordResetResult =
  | { status: "success" }
  | { status: "invalid_token" }
  | { status: "expired_token" }
  | { status: "rate_limited"; retryAfter: number };
