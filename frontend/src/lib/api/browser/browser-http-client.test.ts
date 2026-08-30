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
import { hasLeadingZeroBits } from "@/lib/security/automation-cost";
import {
  registerRiskStepUpHandler,
  RiskStepUpUnavailableError,
} from "@/lib/security/risk-step-up-runtime";

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

function stubFetchSequence(responses: Response[]): { calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      const response = responses[calls.length - 1];
      if (!response) throw new Error("Unexpected fetch call");
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

  it("maps only the constrained reauthToken option onto the step-up header", async () => {
    vi.stubGlobal("document", { cookie: "up_csrf=csrf-token-1" });
    const { calls } = stubFetch(jsonResponse("{}"));

    await browserFetch("/me/security/passkeys/enrollment", {
      method: "POST",
      reauthToken: "grant-opaque",
    });

    expect(headerOf(calls[0], "X-Reauthentication-Token")).toBe("grant-opaque");
    expect(headerOf(calls[0], "X-CSRF-Token")).toBe("csrf-token-1");
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
      expect(error.code).toBe("session.reauthentication_required");
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

describe("browserFetch objective risk step-up", () => {
  function stepUpResponse(stepUp: Record<string, unknown>): Response {
    return jsonResponse(JSON.stringify({
      error: {
        code: "step_up_required",
        message: "需要完成额外验证后继续。",
        stepUp,
      },
    }), 403);
  }

  it("silently solves automation cost, completes it, and retries the exact mutation once", async () => {
    vi.stubGlobal("document", { cookie: "up_csrf=csrf-token-1" });
    const challengeToken = "pow-challenge";
    const { calls } = stubFetchSequence([
      stepUpResponse({
        challengeToken,
        level: "medium",
        method: "automation_cost",
        algorithm: "sha256_leading_zero_bits",
        difficulty: 8,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        providerReady: true,
        completionPath: "/api/v1/auth/step-up",
      }),
      new Response(null, { status: 204 }),
      jsonResponse(JSON.stringify({ status: "ok" })),
    ]);
    const requestBody = { identifier: "account", password: "not-a-real-password" };
    const idempotencyKey = "12345678901234567890123456789012";

    await expect(browserFetch("/auth/sessions", {
      method: "POST",
      body: requestBody,
      idempotencyKey,
    })).resolves.toEqual({ status: "ok" });

    expect(calls.map((call) => call.url)).toEqual([
      "/api/v1/auth/sessions",
      "/api/v1/auth/step-up",
      "/api/v1/auth/sessions",
    ]);
    expect(calls[0].init.body).toBe(calls[2].init.body);
    expect(headerOf(calls[0], "Idempotency-Key")).toBe(idempotencyKey);
    expect(headerOf(calls[2], "Idempotency-Key")).toBe(idempotencyKey);
    const completion = JSON.parse(String(calls[1].init.body)) as {
      challengeToken: string;
      nonce: string;
    };
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(`${completion.challengeToken}:${completion.nonce}`),
    );
    expect(completion.challengeToken).toBe(challengeToken);
    expect(hasLeadingZeroBits(new Uint8Array(digest), 8)).toBe(true);
    expect(headerOf(calls[1], "X-CSRF-Token")).toBe("csrf-token-1");
  });

  it("never loops when the one allowed retry receives another challenge", async () => {
    vi.stubGlobal("document", { cookie: "up_csrf=csrf-token-1" });
    const challenge = {
      challengeToken: "first",
      level: "medium",
      method: "automation_cost",
      algorithm: "sha256_leading_zero_bits",
      difficulty: 1,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      providerReady: true,
      completionPath: "/api/v1/auth/step-up",
    };
    const { calls } = stubFetchSequence([
      stepUpResponse(challenge),
      new Response(null, { status: 204 }),
      stepUpResponse({ ...challenge, challengeToken: "second" }),
    ]);

    const error = await browserFetch("/registrations", {
      method: "POST",
      body: { username: "test" },
    }).catch((caught: unknown) => caught);

    expect(calls).toHaveLength(3);
    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) expect(error.code).toBe("step_up_required");
  });

  it("passes an opaque CAPTCHA proof to the backend before retrying", async () => {
    vi.stubGlobal("document", { cookie: "up_csrf=csrf-token-1" });
    const unregister = registerRiskStepUpHandler(async () => ({
      status: "provider_proof",
      providerProof: "opaque-provider-proof",
    }));
    const { calls } = stubFetchSequence([
      stepUpResponse({
        challengeToken: "captcha-challenge",
        level: "high",
        method: "interactive_captcha",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        providerReady: true,
        provider: "configured-provider",
        providerPayload: { scene: "registration" },
        completionPath: "/api/v1/auth/step-up",
      }),
      new Response(null, { status: 204 }),
      new Response(null, { status: 204 }),
    ]);

    try {
      await expect(browserFetch("/registrations", {
        method: "POST",
        body: { username: "test" },
      })).resolves.toBeUndefined();
    } finally {
      unregister();
    }

    const completion = JSON.parse(String(calls[1].init.body)) as Record<string, unknown>;
    expect(completion).toEqual({
      challengeToken: "captcha-challenge",
      providerProof: "opaque-provider-proof",
    });
  });

  it("fails closed without posting fake proof when the provider is unavailable", async () => {
    vi.stubGlobal("document", { cookie: "up_csrf=csrf-token-1" });
    const unregister = registerRiskStepUpHandler(async () => {
      throw new RiskStepUpUnavailableError("互动验证服务尚未启用，本次请求无法继续。");
    });
    const { calls } = stubFetchSequence([
      stepUpResponse({
        challengeToken: "captcha-unavailable",
        level: "high",
        method: "interactive_captcha",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        providerReady: false,
        completionPath: "/api/v1/auth/step-up",
      }),
    ]);

    let error: unknown;
    try {
      error = await browserFetch("/auth/sessions", {
        method: "POST",
        body: { identifier: "test" },
      }).catch((caught: unknown) => caught);
    } finally {
      unregister();
    }

    expect(calls).toHaveLength(1);
    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) expect(error.message).toContain("尚未启用");
  });
});
