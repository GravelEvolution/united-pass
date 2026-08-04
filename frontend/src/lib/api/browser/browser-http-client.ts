/**
 * Browser-side HTTP client.
 *
 * When the real backend API is available, this module will:
 * - Wrap `fetch` with `credentials: "same-origin"` and `Content-Type: application/json`
 * - Read the CSRF Token from a non-HttpOnly cookie and send it as `X-CSRF-Token`
 *   on write operations (POST, PUT, PATCH, DELETE)
 * - Parse response bodies and handle non-2xx status codes
 * - Return typed results without leaking the `Response` object
 *
 * See ADR-0004 for the full architecture.
 *
 * This file is currently a stub. The mock data source is used directly
 * by `browser-commands.ts` until the backend is available.
 */

export const API_BASE_URL = "/api/v1";

export type BrowserHttpClientOptions = {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
};

export async function browserFetch<T>(
  path: string,
  options: BrowserHttpClientOptions = {},
): Promise<T> {
  const { method = "GET", body, signal } = options;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (method !== "GET") {
    const csrfToken = readCsrfToken();
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: body ? JSON.stringify(body) : undefined,
    signal,
  });

  return parseResponse<T>(response);
}

function readCsrfToken(): string | undefined {
  if (typeof document === "undefined") return undefined;
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
  return match?.[1];
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    // Error normalization will be handled by api-error.ts
    throw new Error(`API request failed: ${response.status} ${response.statusText}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}
