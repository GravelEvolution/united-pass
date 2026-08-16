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

export type ApiError = {
  kind: ApiErrorKind;
  code?: string;
  message: string;
  requestId?: string;
  fieldErrors?: FieldError[];
  retryAfter?: number;
  challenge?: ReauthenticationChallenge;
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

  return true;
}

export function getFieldError(apiError: ApiError, fieldName: string): string | undefined {
  return apiError.fieldErrors?.find((error) => error.field === fieldName)?.message;
}
