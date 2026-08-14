//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-14
// Description: Login-page session redirect regression tests
//

import { afterEach, describe, expect, it, vi } from "vitest";

const sessionState = vi.hoisted(() => ({
  cookie: undefined as string | undefined,
  currentUserError: undefined as unknown,
  currentUserCalls: 0,
}));

vi.mock("@/lib/api/server/server-session", () => ({
  getSessionCookie: async () => sessionState.cookie,
}));

vi.mock("@/lib/api/server/server-queries", () => ({
  serverQueries: {
    getCurrentUser: async () => {
      sessionState.currentUserCalls += 1;
      if (sessionState.currentUserError !== undefined) {
        throw sessionState.currentUserError;
      }
      return {};
    },
  },
}));

import { resolveAuthenticatedLoginDestination } from "./login-session";

afterEach(() => {
  sessionState.cookie = undefined;
  sessionState.currentUserError = undefined;
  sessionState.currentUserCalls = 0;
});

describe("resolveAuthenticatedLoginDestination", () => {
  it("keeps an anonymous visitor on the login page without calling /me", async () => {
    await expect(resolveAuthenticatedLoginDestination()).resolves.toBeUndefined();
    expect(sessionState.currentUserCalls).toBe(0);
  });

  it("redirects a confirmed session to the account center", async () => {
    sessionState.cookie = "active-session";

    await expect(resolveAuthenticatedLoginDestination()).resolves.toBe("/account");
    expect(sessionState.currentUserCalls).toBe(1);
  });

  it("continues an OAuth request for a confirmed session", async () => {
    sessionState.cookie = "active-session";

    await expect(
      resolveAuthenticatedLoginDestination("request/with spaces"),
    ).resolves.toBe("/authorize?requestId=request%2Fwith%20spaces");
  });

  it("keeps an expired or revoked session on the login page", async () => {
    sessionState.cookie = "expired-session";
    sessionState.currentUserError = {
      kind: "unauthorized",
      message: "session expired",
    };

    await expect(resolveAuthenticatedLoginDestination()).resolves.toBeUndefined();
  });

  it("does not disguise backend failures as an anonymous session", async () => {
    const backendError = {
      kind: "server_error" as const,
      message: "backend unavailable",
    };
    sessionState.cookie = "active-session";
    sessionState.currentUserError = backendError;

    await expect(resolveAuthenticatedLoginDestination()).rejects.toBe(backendError);
  });
});
