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
import {
  isApiError,
  isStepUpChallenge,
  type ApiError,
  type FieldError,
  type StepUpChallenge,
} from "@/lib/api/api-error";
import { solveAutomationCost } from "@/lib/security/automation-cost";
import {
  requestRiskStepUp,
  RiskStepUpCancelledError,
  RiskStepUpUnavailableError,
  type RiskStepUpResolution,
} from "@/lib/security/risk-step-up-runtime";

export { BROWSER_API_BASE_URL as API_BASE_URL };

export type BrowserHttpClientOptions = {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
  /** Constrained step-up grant header; callers cannot attach arbitrary headers. */
  reauthToken?: string;
  /** When true, sends body as FormData without setting Content-Type. */
  formData?: boolean;
  /** Optimistic resource version, serialized as a quoted strong ETag. */
  ifMatchVersion?: number;
  /** Caller-generated random idempotency key for a single mutation intent. */
  idempotencyKey?: string;
  /** Aliyun ESA captcha verify parameter, appended as a query param. */
  captchaVerifyParam?: string;
};

export async function browserFetch<T>(
  path: string,
  options: BrowserHttpClientOptions = {},
): Promise<T> {
  const { method = "GET", body, signal, formData, reauthToken, ifMatchVersion, idempotencyKey, captchaVerifyParam } = options;

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

  if (ifMatchVersion !== undefined) {
    if (!Number.isSafeInteger(ifMatchVersion) || ifMatchVersion < 0) {
      throw new TypeError("ifMatchVersion must be a non-negative safe integer");
    }
    headers["If-Match"] = `"${ifMatchVersion}"`;
  }

  if (idempotencyKey) {
    if (!/^[A-Za-z0-9_-]{32,128}$/u.test(idempotencyKey)) {
      throw new TypeError("idempotencyKey has an invalid format");
    }
    headers["Idempotency-Key"] = idempotencyKey;
  }

  const requestBody = formData
    ? (body as FormData | undefined)
    : body !== undefined
      ? JSON.stringify(body)
      : undefined;

  const requestUrl = appendCaptchaParam(browserApiUrl(path), captchaVerifyParam);
  const sendOriginalRequest = (requestHeaders: Record<string, string>) => fetch(
    requestUrl,
    {
      method,
      headers: requestHeaders,
      credentials: "same-origin",
      body: requestBody,
      signal,
    },
  );

  const firstResponse = await sendOriginalRequest(headers);
  if (firstResponse.ok) return parseSuccessResponse<T>(firstResponse);

  const firstError = await normalizeError(firstResponse);
  if (firstError.code !== "step_up_required" || firstError.stepUp === undefined) {
    throw firstError;
  }

  let resolution: RiskStepUpResolution;
  try {
    resolution = await completeRiskStepUp(firstError.stepUp, signal);
  } catch (stepUpError) {
    if (stepUpError instanceof RiskStepUpUnavailableError
      || stepUpError instanceof RiskStepUpCancelledError) {
      throw { ...firstError, message: stepUpError.message } satisfies ApiError;
    }
    throw stepUpError;
  }

  // Exactly one retry is allowed. Reusing the prepared body and header values
  // preserves the original payload and caller-provided Idempotency-Key.
  const retryHeaders = resolution.status === "reauth_granted"
    ? { ...headers, "X-Reauthentication-Token": resolution.reauthToken }
    : headers;
  const retryResponse = await sendOriginalRequest(retryHeaders);
  return parseResponse<T>(retryResponse);
}

function browserApiUrl(path: string): string {
  if (!path.startsWith("/")) throw new TypeError("API path must be same-origin and absolute");
  if (path === BROWSER_API_BASE_URL || path.startsWith(`${BROWSER_API_BASE_URL}/`)) return path;
  return `${BROWSER_API_BASE_URL}${path}`;
}

function appendCaptchaParam(url: string, param: string | undefined): string {
  if (!param) return url;
  const separator = url.includes("?") ? "&" : "?";
  return `${url}${separator}captcha_verify_param=${encodeURIComponent(param)}`;
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

  return parseSuccessResponse<T>(response);
}

async function parseSuccessResponse<T>(response: Response): Promise<T> {
  if (response.status === 204) {
    return undefined as T;
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

async function completeRiskStepUp(
  challenge: StepUpChallenge,
  signal?: AbortSignal,
): Promise<RiskStepUpResolution> {
  switch (challenge.method) {
    case "automation_cost": {
      const nonce = await solveAutomationCost(
        challenge.challengeToken,
        challenge.difficulty,
        signal,
      );
      await postStepUpCompletion(challenge, { nonce }, signal);
      return { status: "completed" };
    }
    case "interactive_captcha": {
      const resolution = await requestRiskStepUp(challenge, signal);
      if (resolution.status !== "provider_proof") {
        throw new RiskStepUpUnavailableError("互动验证未返回有效结果，请重试。")
      }
      await postStepUpCompletion(
        challenge,
        { providerProof: resolution.providerProof },
        signal,
      );
      return { status: "completed" };
    }
    case "mfa": {
      const resolution = await requestRiskStepUp(challenge, signal);
      if (resolution.status !== "completed") {
        throw new RiskStepUpUnavailableError("多因素验证未完成，请重试。")
      }
      return resolution;
    }
    case "reauth": {
      const resolution = await requestRiskStepUp(challenge, signal);
      if (resolution.status !== "reauth_granted") {
        throw new RiskStepUpUnavailableError("身份重新验证未完成，请重试。")
      }
      return resolution;
    }
  }
}

async function postStepUpCompletion(
  challenge: Extract<StepUpChallenge, { method: "automation_cost" | "interactive_captcha" }>,
  proof: { nonce: string } | { providerProof: string },
  signal?: AbortSignal,
): Promise<void> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const csrfToken = readCsrfToken();
  if (csrfToken) headers[CSRF_HEADER_NAME] = csrfToken;

  const response = await fetch(browserApiUrl(challenge.completionPath), {
    method: "POST",
    headers,
    credentials: "same-origin",
    body: JSON.stringify({ challengeToken: challenge.challengeToken, ...proof }),
    signal,
  });
  if (!response.ok) throw await normalizeError(response);
  if (response.status !== 204) {
    throw {
      kind: "server_error",
      code: "step_up_invalid_response",
      message: "额外验证服务返回了无法识别的结果，请重试。",
    } satisfies ApiError;
  }
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

  const code = typeof errorRecord?.code === "string"
    ? errorRecord.code
    : undefined;

  const requestId = typeof errorRecord?.requestId === "string"
    ? errorRecord.requestId
    : undefined;

  const fieldErrors = parseFieldErrors(errorRecord?.fieldErrors);

  const retryAfterHeader = response.headers.get("retry-after");
  const retryAfter = retryAfterHeader ? Number(retryAfterHeader) || undefined : undefined;

  const challenge = parseChallenge(errorRecord?.challenge);
  const stepUp = isStepUpChallenge(errorRecord?.stepUp)
    ? errorRecord.stepUp
    : undefined;

  const kind = statusToKind(response.status, errorRecord?.code);

  const apiError: ApiError = {
    kind,
    ...(code !== undefined && { code }),
    message,
    ...(requestId !== undefined && { requestId }),
    ...(fieldErrors !== undefined && { fieldErrors }),
    ...(retryAfter !== undefined && { retryAfter }),
    ...(challenge !== undefined && { challenge }),
    ...(stepUp !== undefined && { stepUp }),
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
