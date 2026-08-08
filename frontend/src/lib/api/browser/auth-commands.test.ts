//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Contract tests for the login seam against the P1 Session API
//

import { afterEach, describe, expect, it, vi } from "vitest";
import { completeLoginMfa, submitLogin } from "./auth-commands";
import { isApiError } from "@/lib/api/api-error";
import { ApiResponseShapeError } from "@/lib/api/response-validators";

// Node environment: fetch is stubbed explicitly so the suite observes the
// exact request the seam sends and the exact outcome it resolves.

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

function bodyOf(call: FetchCall): Record<string, unknown> {
  return JSON.parse(String(call.init.body)) as Record<string, unknown>;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("submitLogin", () => {
  it("resolves authenticated on 204 (cookies arrive via Set-Cookie)", async () => {
    stubFetch(new Response(null, { status: 204 }));

    const outcome = await submitLogin({
      identifier: "zhixing.lin",
      password: "secret",
      remember: true,
    });

    expect(outcome).toEqual({ status: "authenticated" });
  });

  it("posts the frozen LoginRequest shape including resumeRequestId", async () => {
    const { calls } = stubFetch(new Response(null, { status: 204 }));

    await submitLogin({
      identifier: "zhixing.lin",
      password: "secret",
      remember: false,
      resumeRequestId: "V2-opaque-request",
    });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/api/v1/auth/sessions");
    expect(calls[0].init.method).toBe("POST");
    expect(bodyOf(calls[0])).toEqual({
      identifier: "zhixing.lin",
      password: "secret",
      remember: false,
      resumeRequestId: "V2-opaque-request",
    });
  });

  it("defaults resumeRequestId to an empty string so the backend field stays present", async () => {
    const { calls } = stubFetch(new Response(null, { status: 204 }));

    await submitLogin({ identifier: "a", password: "b", remember: true });

    expect(bodyOf(calls[0]).resumeRequestId).toBe("");
  });

  it("narrows a 202 body onto the mfa_required challenge", async () => {
    stubFetch(
      jsonResponse(
        JSON.stringify({
          status: "mfa_required",
          mfaToken: "opaque-mfa-token",
          availableMethods: ["totp"],
          expiresAt: "2026-08-07T12:05:30Z",
        }),
        202,
      ),
    );

    const outcome = await submitLogin({
      identifier: "zhixing.lin",
      password: "secret",
      remember: false,
    });

    expect(outcome).toEqual({
      status: "mfa_required",
      mfaToken: "opaque-mfa-token",
      availableMethods: ["totp"],
    });
  });

  it("rejects a 202 body whose method is outside the frozen contract", async () => {
    stubFetch(
      jsonResponse(
        JSON.stringify({
          status: "mfa_required",
          mfaToken: "t",
          availableMethods: ["sms"],
        }),
        202,
      ),
    );

    await expect(
      submitLogin({ identifier: "a", password: "b", remember: false }),
    ).rejects.toThrow(ApiResponseShapeError);
  });

  it("normalizes 401 into an ApiError without revealing account existence", async () => {
    stubFetch(
      jsonResponse(
        JSON.stringify({
          error: { code: "auth.invalid_credentials", message: "账户名或密码错误。" },
        }),
        401,
      ),
    );

    const error = await submitLogin({
      identifier: "nobody",
      password: "wrong",
      remember: false,
    }).catch((value) => value);

    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) {
      expect(error.kind).toBe("unauthorized");
    }
  });

  it("surfaces 429 with the Retry-After budget", async () => {
    const response = jsonResponse(
      JSON.stringify({
        error: { code: "auth.rate_limited", message: "尝试次数过多。" },
      }),
      429,
    );
    response.headers.set("retry-after", "42");
    stubFetch(response);

    const error = await submitLogin({
      identifier: "a",
      password: "b",
      remember: false,
    }).catch((value) => value);

    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) {
      expect(error.kind).toBe("rate_limited");
      expect(error.retryAfter).toBe(42);
    }
  });
});

describe("completeLoginMfa", () => {
  it("posts the challenge and resolves on 204", async () => {
    const { calls } = stubFetch(new Response(null, { status: 204 }));

    await completeLoginMfa({ mfaToken: "tok", method: "totp", code: "123456" });

    expect(calls[0].url).toBe("/api/v1/auth/sessions/mfa");
    expect(calls[0].init.method).toBe("POST");
    expect(bodyOf(calls[0])).toEqual({
      mfaToken: "tok",
      method: "totp",
      code: "123456",
    });
  });

  it("omits the code field when it is not provided", async () => {
    const { calls } = stubFetch(new Response(null, { status: 204 }));

    await completeLoginMfa({ mfaToken: "tok", method: "passkey", passkeyAssertion: { id: "c1" } });

    expect(bodyOf(calls[0])).toEqual({
      mfaToken: "tok",
      method: "passkey",
      passkeyAssertion: { id: "c1" },
    });
  });

  it("rejects with an ApiError on 401 (wrong code / expired challenge)", async () => {
    stubFetch(
      jsonResponse(
        JSON.stringify({
          error: { code: "auth.invalid_credentials", message: "验证码错误。剩余尝试次数 2 次。" },
        }),
        401,
      ),
    );

    const error = await completeLoginMfa({
      mfaToken: "tok",
      method: "totp",
      code: "000000",
    }).catch((value) => value);

    expect(isApiError(error)).toBe(true);
    if (isApiError(error)) {
      expect(error.kind).toBe("unauthorized");
    }
  });
});
