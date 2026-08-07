//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Security regression tests for the browser HTTP client
//

import { afterEach, describe, expect, it, vi } from "vitest";
import { browserFetch } from "./browser-http-client";
import { isApiError } from "@/lib/api/api-error";

// The suite runs in vitest's node environment: `fetch` and the CSRF cookie
// surface (`document.cookie`) are stubbed explicitly, so every assertion
// observes exactly what the client sends and does.

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
});

describe("browserFetch CSRF wiring", () => {
  it("attaches the CSRF cookie as X-CSRF-Token on write operations", async () => {
    vi.stubGlobal("document", { cookie: "up_csrf=csrf-token-1; other=x" });
    const { calls } = stubFetch(jsonResponse("{}"));

    await browserFetch("/consent/V2-1/decision", { method: "POST", body: { decision: "allow" } });

    expect(calls).toHaveLength(1);
    expect(headerOf(calls[0], "X-CSRF-Token")).toBe("csrf-token-1");
    expect(calls[0].init.credentials).toBe("same-origin");
  });

  it("never sends a CSRF header on GET", async () => {
    vi.stubGlobal("document", { cookie: "up_csrf=csrf-token-1" });
    const { calls } = stubFetch(jsonResponse("{}"));

    await browserFetch("/me");

    expect(headerOf(calls[0], "X-CSRF-Token")).toBeNull();
  });

  it("still sends the write without a header when the CSRF cookie is absent", async () => {
    vi.stubGlobal("document", { cookie: "" });
    const { calls } = stubFetch(jsonResponse("{}"));

    await browserFetch("/x", { method: "DELETE" });

    expect(headerOf(calls[0], "X-CSRF-Token")).toBeNull();
  });
});

describe("browserFetch response parsing contract", () => {
  it("returns undefined for 204 No Content", async () => {
    vi.stubGlobal("document", { cookie: "" });
    stubFetch(new Response(null, { status: 204 }));

    await expect(browserFetch("/grants/g1", { method: "DELETE" })).resolves.toBeUndefined();
  });

  it("FAILS on 2xx with malformed JSON — never succeeds with undefined", async () => {
    // P3.8 pin: a 200 whose JSON body is corrupt is a transport failure.
    // The parse error may stay a raw SyntaxError (wrapping into ApiError
    // is not required) but it must surface as a rejection, because
    // returning undefined here would masquerade as a successful empty
    // response. Business-shape protection is the response-validators
    // second layer, not this transport.
    vi.stubGlobal("document", { cookie: "" });
    stubFetch(jsonResponse("{not valid json"));

    await expect(browserFetch("/me")).rejects.toThrow();
  });

  it("returns undefined on 2xx with a non-JSON Content-Type (current transport contract)", async () => {
    // P3.8 pin of the CURRENT contract: the client does not reject
    // non-JSON success bodies itself — it yields undefined, and the
    // migrated seams fail closed later through their response validators.
    // Do not reinterpret this as client-side content-type enforcement.
    vi.stubGlobal("document", { cookie: "" });
    stubFetch(new Response("<html>", { status: 200, headers: { "Content-Type": "text/html" } }));

    await expect(browserFetch("/me")).resolves.toBeUndefined();
  });
});

describe("browserFetch error normalization", () => {
  const cases: Array<[number, string]> = [
    [401, "unauthorized"],
    [403, "forbidden"],
    [404, "not_found"],
    [409, "conflict"],
    [400, "validation"],
    [422, "validation"],
    [429, "rate_limited"],
    [500, "server_error"],
  ];

  it.each(cases)("normalizes %i onto kind %s", async (status, kind) => {
    vi.stubGlobal("document", { cookie: "" });
    stubFetch(jsonResponse(JSON.stringify({ error: { message: "失败" } }), status));

    const error = await browserFetch("/x").catch((e: unknown) => e);

    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) {
      expect(error.kind).toBe(kind);
      expect(error.message).toBe("失败");
    }
  });

  it("keeps the reauthentication code over the plain 401 kind", async () => {
    vi.stubGlobal("document", { cookie: "" });
    stubFetch(
      jsonResponse(
        JSON.stringify({ error: { code: "session.reauthentication_required", message: "需要重新验证" } }),
        401,
      ),
    );

    const error = await browserFetch("/x").catch((e: unknown) => e);

    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) {
      expect(error.kind).toBe("reauthentication_required");
    }
  });

  it("parses retryAfter, fieldErrors and challenge from the error body", async () => {
    vi.stubGlobal("document", { cookie: "" });
    stubFetch(
      jsonResponse(
        JSON.stringify({
          error: {
            message: "请求无效",
            requestId: "req-1",
            fieldErrors: [
              { field: "email", message: "必填" },
              { field: "", message: "dropped" },
            ],
            challenge: { methods: ["password", "unknown-method"], requestId: "mfa-1" },
          },
        }),
        429,
      ),
    );

    // 429 body above wins over the headerless retry-after; add the header too.
    const error = await browserFetch("/x").catch((e: unknown) => e);

    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) {
      expect(error.kind).toBe("rate_limited");
      expect(error.requestId).toBe("req-1");
      expect(error.fieldErrors).toEqual([{ field: "email", message: "必填" }]);
      expect(error.challenge).toEqual({ methods: ["password"], requestId: "mfa-1" });
    }
  });

  it("reads the Retry-After header on rate-limited responses", async () => {
    vi.stubGlobal("document", { cookie: "" });
    stubFetch(
      new Response(JSON.stringify({ error: { message: "太快了" } }), {
        status: 429,
        headers: { "Content-Type": "application/json", "Retry-After": "12" },
      }),
    );

    const error = await browserFetch("/x").catch((e: unknown) => e);

    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) {
      expect(error.retryAfter).toBe(12);
    }
  });

  it("normalizes a non-JSON error body onto a server-side kind with a fallback message", async () => {
    vi.stubGlobal("document", { cookie: "" });
    stubFetch(new Response("<html>bad gateway</html>", { status: 502 }));

    const error = await browserFetch("/x").catch((e: unknown) => e);

    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) {
      expect(error.kind).toBe("server_error");
      expect(error.message).toContain("502");
    }
  });

  it("falls back to server_error when the body carries no usable error envelope", async () => {
    vi.stubGlobal("document", { cookie: "" });
    stubFetch(jsonResponse(JSON.stringify({ unexpected: true }), 418));

    const error = await browserFetch("/x").catch((e: unknown) => e);

    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) {
      expect(error.kind).toBe("server_error");
    }
  });
});
