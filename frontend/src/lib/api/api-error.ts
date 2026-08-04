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
  message: string;
  requestId?: string;
  fieldErrors?: FieldError[];
  retryAfter?: number;
  challenge?: ReauthenticationChallenge;
};

export function isApiError(value: unknown): value is ApiError {
  return (
    typeof value === "object" &&
    value !== null &&
    "kind" in value &&
    "message" in value
  );
}

export function getFieldError(apiError: ApiError, fieldName: string): string | undefined {
  return apiError.fieldErrors?.find((error) => error.field === fieldName)?.message;
}
