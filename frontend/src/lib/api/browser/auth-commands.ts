//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Browser-side login seam against the P1 Session API
//

"use client";

import type { MfaMethod } from "@/features/auth/types";
import { browserFetch } from "@/lib/api/browser/browser-http-client";
import { parseMfaRequiredResponse } from "@/lib/api/response-validators";

/**
 * Login seam (P3.9 prerequisite, frontend-freeze-v1.md §5, ADR-0004).
 *
 * `/login` always submits credentials to the P1 Session API; the product-data
 * fixture switch cannot manufacture an authenticated browser state:
 *
 *   POST /api/v1/auth/sessions
 *     204 → session cookies set, login complete
 *     202 → MFA required; complete via POST /api/v1/auth/sessions/mfa
 *
 * The opaque authorization `requestId` is preserved by the caller (the login
 * page keeps it in state across the MFA step) and forwarded as
 * `resumeRequestId` so the backend can bind the login to the pending
 * authorization transaction. After success the browser navigates to
 * `/authorize?requestId=...` — the requestId never leaves the URL/state
 * round-trip and is never replaced by a raw returnTo URL.
 */

export type LoginInput = {
  identifier: string;
  password: string;
  remember: boolean;
  resumeRequestId?: string;
};

export type LoginOutcome =
  | { status: "authenticated" }
  | {
      status: "mfa_required";
      mfaToken: string;
      availableMethods: MfaMethod[];
      passkeyRequestOptions?: unknown;
      expiresAt: string;
    };

/**
 * Submits the password login. Resolves `{ status: "authenticated" }` on 204
 * (session cookies arrive via Set-Cookie) or the narrowed `mfa_required`
 * challenge on 202. Non-2xx statuses reject with the normalized ApiError.
 */
export async function submitLogin(input: LoginInput): Promise<LoginOutcome> {
  const body = await browserFetch<unknown>("/auth/sessions", {
    method: "POST",
    body: {
      identifier: input.identifier,
      password: input.password,
      remember: input.remember,
      resumeRequestId: input.resumeRequestId ?? "",
    },
  });

  // 204 carries no body: the transport layer resolves undefined, which is
  // the authenticated outcome (cookies were set by the server).
  if (body === undefined || body === null) {
    return { status: "authenticated" };
  }

  return { status: "mfa_required", ...parseMfaRequiredResponse(body) };
}

export type LoginMfaInput = {
  mfaToken: string;
  method: MfaMethod;
  /** TOTP / recovery code payload. */
  code?: string;
  /** Raw WebAuthn assertion JSON for the passkey method. */
  passkeyAssertion?: unknown;
};

/**
 * Completes the MFA challenge started by `submitLogin`. Resolves on 204
 * (session established); failures reject with the normalized ApiError
 * (wrong code, expired challenge, rate limit).
 */
export async function completeLoginMfa(input: LoginMfaInput): Promise<void> {
  await browserFetch<unknown>("/auth/sessions/mfa", {
    method: "POST",
    body: {
      mfaToken: input.mfaToken,
      method: input.method,
      ...(input.code !== undefined && { code: input.code }),
      ...(input.passkeyAssertion !== undefined && {
        passkeyAssertion: input.passkeyAssertion,
      }),
    },
  });
}

export type RegistrationInput = {
  username: string;
  email: string;
  password: string;
  termsAccepted: true;
};

export type RegistrationOutcome = {
  userId: string;
  status: "email_verification_required";
};

export async function registerAccount(input: RegistrationInput): Promise<RegistrationOutcome> {
  const value = await browserFetch<unknown>("/registrations", {
    method: "POST",
    body: input,
  });
  if (typeof value !== "object" || value === null) {
    throw new Error("Registration response has an invalid shape");
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record.userId !== "string" ||
    record.userId.length === 0 ||
    record.status !== "email_verification_required"
  ) {
    throw new Error("Registration response has an invalid shape");
  }
  return { userId: record.userId, status: record.status };
}

export async function requestPasswordReset(identifier: string): Promise<void> {
  await browserFetch<unknown>("/password-reset-requests", {
    method: "POST",
    body: { identifier },
  });
}

export async function resetAccountPassword(input: {
  token: string;
  code: string;
  newPassword: string;
}): Promise<void> {
  await browserFetch<unknown>("/password-resets", {
    method: "POST",
    body: input,
  });
}

export async function verifyAccountEmail(
  input: { token: string; code: string },
  signal?: AbortSignal,
): Promise<void> {
  await browserFetch<unknown>("/email-verifications", {
    method: "POST",
    body: input,
    signal,
  });
}
