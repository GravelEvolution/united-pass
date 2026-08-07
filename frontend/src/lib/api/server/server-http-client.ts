//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Server-side HTTP client wrapper
//

import { cookies, headers as nextHeaders } from "next/headers";
import {
  SERVER_API_BASE_URL,
  SESSION_COOKIE_NAME,
} from "@/lib/api/constants";
import { isApiError, type ApiError, type FieldError } from "@/lib/api/api-error";

/**
 * Server-side HTTP client.
 *
 * Wraps `fetch` with:
 * - Session cookie forwarding via `next/headers` cookies()
 * - `cache: "no-store"` to prevent caching user-specific responses
 * - Request ID forwarding from incoming headers for distributed tracing
 * - ApiError normalization for non-2xx status codes
 *
 * See ADR-0004 for the API client architecture.
 * See ADR-0006 for the Cookie naming and deployment topology.
 */

export { SERVER_API_BASE_URL as API_BASE_URL };

export type ServerHttpClientOptions = {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
};

export async function serverFetch<T>(
  path: string,
  options: ServerHttpClientOptions = {},
): Promise<T> {
  const { method = "GET", body, signal } = options;

  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get(SESSION_COOKIE_NAME);

  const headerStore = await nextHeaders();
  const requestId = headerStore.get("x-request-id");

  const requestHeaders: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (sessionCookie) {
    requestHeaders["Cookie"] = `${SESSION_COOKIE_NAME}=${sessionCookie.value}`;
  }

  if (requestId) {
    requestHeaders["X-Request-ID"] = requestId;
  }

  const response = await fetch(`${SERVER_API_BASE_URL}${path}`, {
    method,
    headers: requestHeaders,
    body: body ? JSON.stringify(body) : undefined,
    signal,
    cache: "no-store",
  });

  return parseResponse<T>(response);
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
