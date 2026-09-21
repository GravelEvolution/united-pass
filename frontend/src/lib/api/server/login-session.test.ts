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
  consentResolution: { status: "valid" } as { status: string },
  consentResolutionError: undefined as unknown,
  consentResolutionCalls: [] as string[],
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
    getConsentResolution: async (requestId: string) => {
      sessionState.consentResolutionCalls.push(requestId);
      if (sessionState.consentResolutionError !== undefined) {
        throw sessionState.consentResolutionError;
      }
      return sessionState.consentResolution;
    },
  },
}));

import { resolveAuthenticatedLoginDestination } from "./login-session";

afterEach(() => {
  sessionState.cookie = undefined;
  sessionState.currentUserError = undefined;
  sessionState.currentUserCalls = 0;
  sessionState.consentResolution = { status: "valid" };
  sessionState.consentResolutionError = undefined;
  sessionState.consentResolutionCalls = [];
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

  it("continues an OAuth request when its resolution accepts the confirmed session", async () => {
    sessionState.cookie = "active-session";

    await expect(
      resolveAuthenticatedLoginDestination("request/with spaces"),
    ).resolves.toBe("/authorize?requestId=request%2Fwith%20spaces");
    expect(sessionState.currentUserCalls).toBe(1);
    expect(sessionState.consentResolutionCalls).toEqual(["request/with spaces"]);
  });

  it("keeps a fresh-auth authorization request on login despite a valid generic session", async () => {
    sessionState.cookie = "active-session";
    sessionState.consentResolution = { status: "unauthenticated" };

    await expect(
      resolveAuthenticatedLoginDestination("V2_fresh_auth_request"),
    ).resolves.toBeUndefined();
    expect(sessionState.currentUserCalls).toBe(1);
    expect(sessionState.consentResolutionCalls).toEqual(["V2_fresh_auth_request"]);
  });

  it.each(["already_authorized", "expired", "client_not_found", "redirect_mismatch", "scope_not_allowed"])(
    "sends a %s authorization result to authorize for stable handling",
    async (status) => {
      sessionState.cookie = "active-session";
      sessionState.consentResolution = { status };

      await expect(
        resolveAuthenticatedLoginDestination("V2_terminal_request"),
      ).resolves.toBe("/authorize?requestId=V2_terminal_request");
      expect(sessionState.consentResolutionCalls).toEqual(["V2_terminal_request"]);
    },
  );

  it("does not resolve an authorization request when the generic session is invalid", async () => {
    sessionState.cookie = "expired-session";
    sessionState.currentUserError = {
      kind: "unauthorized",
      message: "session expired",
    };

    await expect(
      resolveAuthenticatedLoginDestination("V2_request"),
    ).resolves.toBeUndefined();
    expect(sessionState.consentResolutionCalls).toEqual([]);
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

  it("does not disguise authorization-resolution failures as a login form", async () => {
    const backendError = {
      kind: "server_error" as const,
      message: "authorization backend unavailable",
    };
    sessionState.cookie = "active-session";
    sessionState.consentResolutionError = backendError;

    await expect(
      resolveAuthenticatedLoginDestination("V2_request"),
    ).rejects.toBe(backendError);
  });
});
