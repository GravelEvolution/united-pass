//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Browser-side HTTP client wrapper
//

/**
 * Browser-side HTTP client.
 *
 * Wraps `fetch` with `credentials: "same-origin"` and `Content-Type: application/json`.
 * Reads the CSRF Token from the `up_csrf` non-HttpOnly cookie and sends it as
 * `X-CSRF-Token` on write operations (POST, PUT, PATCH, DELETE).
 * Parses response bodies and normalizes non-2xx status codes into `ApiError`.
 *
 * See ADR-0004 for the API client architecture.
 * See ADR-0006 for the Cookie naming and deployment topology.
 */

import {
  BROWSER_API_BASE_URL,
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
} from "@/lib/api/constants";
import { isApiError, type ApiError, type FieldError } from "@/lib/api/api-error";

export { BROWSER_API_BASE_URL as API_BASE_URL };

export type BrowserHttpClientOptions = {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
  /** Constrained step-up grant header; callers cannot attach arbitrary headers. */
  reauthToken?: string;
  /** When true, sends body as FormData without setting Content-Type. */
  formData?: boolean;
};

export async function browserFetch<T>(
  path: string,
  options: BrowserHttpClientOptions = {},
): Promise<T> {
  const { method = "GET", body, signal, formData, reauthToken } = options;

  const headers: Record<string, string> = {};

  if (!formData) {
    headers["Content-Type"] = "application/json";
  }

  if (method !== "GET") {
    const csrfToken = readCsrfToken();
    if (csrfToken) {
      headers[CSRF_HEADER_NAME] = csrfToken;
    }
  }

  if (reauthToken) {
    headers["X-Reauthentication-Token"] = reauthToken;
  }

  const response = await fetch(`${BROWSER_API_BASE_URL}${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: formData
      ? (body as FormData | undefined)
      : body
        ? JSON.stringify(body)
        : undefined,
    signal,
  });

  return parseResponse<T>(response);
}

function readCsrfToken(): string | undefined {
  if (typeof document === "undefined") return undefined;
  const prefix = `${CSRF_COOKIE_NAME}=`;
  const match = document.cookie
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(prefix));
  return match?.slice(prefix.length);
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    throw await normalizeError(response);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

async function normalizeError(response: Response): Promise<ApiError> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = null;
  }

  const errorObj = body && typeof body === "object"
    ? (body as Record<string, unknown>).error
    : null;
  const errorRecord = errorObj && typeof errorObj === "object"
    ? errorObj as Record<string, unknown>
    : null;

  const message = typeof errorRecord?.message === "string"
    ? errorRecord.message
    : `API request failed: ${response.status} ${response.statusText}`;

  const requestId = typeof errorRecord?.requestId === "string"
    ? errorRecord.requestId
    : undefined;

  const fieldErrors = parseFieldErrors(errorRecord?.fieldErrors);

  const retryAfterHeader = response.headers.get("retry-after");
  const retryAfter = retryAfterHeader ? Number(retryAfterHeader) || undefined : undefined;

  const challenge = parseChallenge(errorRecord?.challenge);

  const kind = statusToKind(response.status, errorRecord?.code);

  const apiError: ApiError = {
    kind,
    message,
    ...(requestId !== undefined && { requestId }),
    ...(fieldErrors !== undefined && { fieldErrors }),
    ...(retryAfter !== undefined && { retryAfter }),
    ...(challenge !== undefined && { challenge }),
  };

  if (isApiError(apiError)) {
    return apiError;
  }

  return {
    kind: "server_error",
    message,
  };
}

function statusToKind(status: number, code: unknown): ApiError["kind"] {
  if (code === "session.reauthentication_required") return "reauthentication_required";
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 422 || status === 400) return "validation";
  if (status === 429) return "rate_limited";
  return "server_error";
}

function parseFieldErrors(value: unknown): FieldError[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value
    .filter(
      (item): item is Record<string, unknown> =>
        typeof item === "object" && item !== null,
    )
    .map((item) => ({
      field: String(item.field ?? ""),
      message: String(item.message ?? ""),
    }))
    .filter((item) => item.field && item.message);
}

function parseChallenge(value: unknown): ApiError["challenge"] {
  if (typeof value !== "object" || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.methods)) return undefined;
  if (typeof record.requestId !== "string") return undefined;

  const methods = record.methods.filter(
    (m): m is "password" | "totp" | "passkey" =>
      m === "password" || m === "totp" || m === "passkey",
  );

  if (methods.length === 0) return undefined;

  return { methods, requestId: record.requestId };
}
