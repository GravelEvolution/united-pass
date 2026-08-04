import { cookies } from "next/headers";

/**
 * Server-side HTTP client.
 *
 * When the real backend API is available, this module will:
 * - Wrap `fetch` without `credentials` (server has no browser credentials)
 * - Read the user's session cookie via `next/headers` cookies() and forward
 *   it as a `Cookie` header to the backend API
 * - NOT send CSRF tokens (server-to-backend requests don't need CSRF protection)
 * - Parse response bodies and handle non-2xx status codes
 * - Return typed results without leaking the `Response` object
 *
 * See ADR-0004 for the full architecture.
 *
 * This file is currently a stub. The mock data source is used directly
 * by `server-queries.ts` until the backend is available.
 */

export const API_BASE_URL = process.env.API_BASE_URL ?? "http://localhost:8080/api/v1";

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
  const sessionCookie = cookieStore.get("session");

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (sessionCookie) {
    headers["Cookie"] = `session=${sessionCookie.value}`;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal,
  });

  return parseResponse<T>(response);
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status} ${response.statusText}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}
