//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: API error parsing and classification
//

/**
 * Unified error types for the API client layer.
 *
 * See docs/adr-0004.md for the full decision context.
 * These types are consumed by the future HTTP-based UnitedPassDataSource
 * implementation and by Client Components that need to render field-level
 * or page-level errors.
*/

import {
  FIRST_PARTY_IMAGE_PROVIDER,
  parseInteractiveCaptchaDescriptor,
  RECAPTCHA_PROVIDER,
  TURNSTILE_PROVIDER,
} from "@/lib/security/interactive-captcha-contract";

export type ApiErrorKind =
  | "network"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "validation"
  | "rate_limited"
  | "reauthentication_required"
  | "server_error";

export type FieldError = {
  field: string;
  message: string;
};

export type ReauthenticationChallenge = {
  methods: ReadonlyArray<"password" | "totp" | "passkey">;
  requestId: string;
};

type StepUpBase = {
  challengeToken: string;
  level: "medium" | "high";
  expiresAt: string;
  providerReady: boolean;
};

export type AutomationCostStepUp = StepUpBase & {
  method: "automation_cost";
  algorithm: "sha256_leading_zero_bits";
  difficulty: number;
  completionPath: "/api/v1/auth/step-up";
};

export type InteractiveCaptchaStepUp = StepUpBase & {
  method: "interactive_captcha";
  completionPath: "/api/v1/auth/step-up";
} & (
  | {
    providerReady: false;
    provider?: never;
    providerPayload?: never;
  }
  | {
    providerReady: true;
    provider: typeof TURNSTILE_PROVIDER;
    providerPayload: Readonly<{ siteKey: string; action: string; cdata: string }>;
  }
  | {
    providerReady: true;
    provider: typeof RECAPTCHA_PROVIDER;
    providerPayload: Readonly<{ siteKey: string; action: string }>;
  }
  | {
    providerReady: true;
    provider: typeof FIRST_PARTY_IMAGE_PROVIDER;
    providerPayload: Readonly<{ imageDataUrl: string; digits: number }>;
  }
);

/**
 * Forward-compatible account-aware methods. The current pre-authentication
 * risk gate does not emit these; login MFA and authenticated reauthentication
 * retain their existing API contracts.
 */
export type AccountAwareStepUp = StepUpBase & (
  | {
    method: "mfa";
    completionPath: "/api/v1/auth/sessions/mfa";
    provider?: string;
    providerPayload?: Readonly<Record<string, unknown>>;
  }
  | {
    method: "reauth";
    completionPath: "/api/v1/auth/reauthentication";
    provider?: string;
    providerPayload?: Readonly<Record<string, unknown>>;
  }
);

export type StepUpChallenge =
  | AutomationCostStepUp
  | InteractiveCaptchaStepUp
  | AccountAwareStepUp;

export type ApiError = {
  kind: ApiErrorKind;
  code?: string;
  message: string;
  requestId?: string;
  fieldErrors?: FieldError[];
  retryAfter?: number;
  challenge?: ReauthenticationChallenge;
  stepUp?: StepUpChallenge;
  /**
   * A step-up-backed login failed after verification, or its completion became
   * ambiguous. Login uses this local-only marker to reload before another
   * credential attempt, preventing any completed challenge UI from being
   * mistaken for a reusable grant.
   */
  requiresChallengeRefresh?: true;
};

const API_ERROR_KINDS: ReadonlySet<string> = new Set<ApiErrorKind>([
  "network",
  "unauthorized",
  "forbidden",
  "not_found",
  "conflict",
  "validation",
  "rate_limited",
  "reauthentication_required",
  "server_error",
]);

function isFieldErrorArray(value: unknown): value is FieldError[] {
  if (!Array.isArray(value)) return false;
  return value.every(
    (item) =>
      typeof item === "object" &&
      item !== null &&
      typeof (item as Record<string, unknown>).field === "string" &&
      typeof (item as Record<string, unknown>).message === "string",
  );
}

function isReauthenticationChallenge(value: unknown): value is ReauthenticationChallenge {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.methods)) return false;
  if (!record.methods.every((m) => m === "password" || m === "totp" || m === "passkey")) return false;
  return typeof record.requestId === "string";
}

export function isStepUpChallenge(value: unknown): value is StepUpChallenge {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (typeof record.challengeToken !== "string"
    || record.challengeToken.length === 0
    || record.challengeToken.length > 512) return false;
  if (record.level !== "medium" && record.level !== "high") return false;
  if (typeof record.expiresAt !== "string" || Number.isNaN(Date.parse(record.expiresAt))) return false;
  if (typeof record.providerReady !== "boolean") return false;
  if (record.provider !== undefined && typeof record.provider !== "string") return false;
  if (record.providerPayload !== undefined
    && (typeof record.providerPayload !== "object"
      || record.providerPayload === null
      || Array.isArray(record.providerPayload))) return false;

  switch (record.method) {
    case "automation_cost":
      return record.providerReady === true
        && record.provider === undefined
        && record.providerPayload === undefined
        && record.completionPath === "/api/v1/auth/step-up"
        && record.algorithm === "sha256_leading_zero_bits"
        && Number.isSafeInteger(record.difficulty)
        && typeof record.difficulty === "number"
        && record.difficulty >= 1
        && record.difficulty <= 30;
    case "interactive_captcha":
      if (record.completionPath !== "/api/v1/auth/step-up") return false;
      if (!record.providerReady) {
        return record.provider === undefined && record.providerPayload === undefined;
      }
      return parseInteractiveCaptchaDescriptor(record.provider, record.providerPayload) !== undefined;
    case "mfa":
      return record.completionPath === "/api/v1/auth/sessions/mfa";
    case "reauth":
      return record.completionPath === "/api/v1/auth/reauthentication";
    default:
      return false;
  }
}

export function isApiError(value: unknown): value is ApiError {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;

  if (typeof record.kind !== "string" || !API_ERROR_KINDS.has(record.kind)) return false;
  if (typeof record.message !== "string") return false;

  if (record.code !== undefined && typeof record.code !== "string") return false;
  if (record.requestId !== undefined && typeof record.requestId !== "string") return false;
  if (record.fieldErrors !== undefined && !isFieldErrorArray(record.fieldErrors)) return false;
  if (record.retryAfter !== undefined && typeof record.retryAfter !== "number") return false;
  if (record.challenge !== undefined && !isReauthenticationChallenge(record.challenge)) return false;
  if (record.stepUp !== undefined && !isStepUpChallenge(record.stepUp)) return false;
  if (record.requiresChallengeRefresh !== undefined && record.requiresChallengeRefresh !== true) return false;

  return true;
}

export function getFieldError(apiError: ApiError, fieldName: string): string | undefined {
  return apiError.fieldErrors?.find((error) => error.field === fieldName)?.message;
}
