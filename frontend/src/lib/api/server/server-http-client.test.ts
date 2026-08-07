//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Security regression tests for the server HTTP client
//

import { afterEach, describe, expect, it, vi } from "vitest";

// Mutable next/headers state shared with the module mock below. vi.hoisted
// keeps the carrier alive across the vi.mock/import hoisting order.
const nextHeadersState = vi.hoisted(() => ({
  sessionCookie: undefined as string | undefined,
  requestId: null as string | null,
}));

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      name === "up_session" && nextHeadersState.sessionCookie !== undefined
        ? { name, value: nextHeadersState.sessionCookie }
        : undefined,
  }),
  headers: async () => ({
    get: (name: string) => (name === "x-request-id" ? nextHeadersState.requestId : null),
  }),
}));

import { serverFetch } from "./server-http-client";
import { isApiError } from "@/lib/api/api-error";

type FetchCall = {
  url: string;
  init: RequestInit;
};

function stubFetch(response: Response): { calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return response;
    }),
  );
  return { calls };
}

function jsonResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function headerOf(call: FetchCall, name: string): string | null {
  return new Headers(call.init.headers as HeadersInit).get(name);
}

afterEach(() => {
  vi.unstubAllGlobals();
  nextHeadersState.sessionCookie = undefined;
  nextHeadersState.requestId = null;
});

describe("serverFetch session-cookie forwarding", () => {
  it("forwards exactly the session cookie and nothing else", async () => {
    nextHeadersState.sessionCookie = "sealed-session-value";
    const { calls } = stubFetch(jsonResponse("{}"));

    await serverFetch("/authorize/V2-1");

    expect(calls).toHaveLength(1);
    expect(headerOf(calls[0], "Cookie")).toBe("up_session=sealed-session-value");
  });

  it("omits the Cookie header entirely when no session exists", async () => {
    const { calls } = stubFetch(jsonResponse("{}"));

    await serverFetch("/authorize/V2-1");

    expect(headerOf(calls[0], "Cookie")).toBeNull();
  });

  it("forwards the incoming x-request-id for tracing", async () => {
    nextHeadersState.requestId = "trace-123";
    const { calls } = stubFetch(jsonResponse("{}"));

    await serverFetch("/authorize/V2-1");

    expect(headerOf(calls[0], "X-Request-ID")).toBe("trace-123");
  });
});

describe("serverFetch caching contract", () => {
  it("always fetches with cache no-store — user-specific responses never cached", async () => {
    nextHeadersState.sessionCookie = "s";
    const { calls } = stubFetch(jsonResponse("{}"));

    await serverFetch("/me");

    expect(calls[0].init.cache).toBe("no-store");
  });
});

describe("serverFetch response parsing contract", () => {
  it("returns undefined for 204 No Content", async () => {
    stubFetch(new Response(null, { status: 204 }));

    await expect(serverFetch("/x")).resolves.toBeUndefined();
  });

  it("FAILS on 2xx with malformed JSON — never succeeds with undefined", async () => {
    // Same P3.8 pin as the browser client: corrupt JSON on a success
    // status is a transport failure, never a silent undefined.
    stubFetch(jsonResponse("{not valid json"));

    await expect(serverFetch("/authorize/V2-1")).rejects.toThrow();
  });

  it("returns undefined on 2xx with a non-JSON Content-Type (current transport contract)", async () => {
    // Current contract: the client yields undefined; the migrated seams'
    // response validators fail closed on the missing shape. This is not
    // client-side content-type rejection.
    stubFetch(new Response("<html>", { status: 200, headers: { "Content-Type": "text/html" } }));

    await expect(serverFetch("/authorize/V2-1")).resolves.toBeUndefined();
  });
});

describe("serverFetch error normalization", () => {
  const cases: Array<[number, string]> = [
    [401, "unauthorized"],
    [403, "forbidden"],
    [404, "not_found"],
    [409, "conflict"],
    [400, "validation"],
    [429, "rate_limited"],
    [503, "server_error"],
  ];

  it.each(cases)("normalizes %i onto kind %s", async (status, kind) => {
    stubFetch(jsonResponse(JSON.stringify({ error: { message: "失败" } }), status));

    const error = await serverFetch("/x").catch((e: unknown) => e);

    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) {
      expect(error.kind).toBe(kind);
    }
  });

  it("normalizes a non-JSON error body with a fallback message", async () => {
    stubFetch(new Response("upstream down", { status: 502 }));

    const error = await serverFetch("/x").catch((e: unknown) => e);

    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) {
      expect(error.kind).toBe("server_error");
      expect(error.message).toContain("502");
    }
  });
});
