
import { afterEach, describe, expect, it, vi } from "vitest";

const sessionState = vi.hoisted(() => ({
  cookie: undefined as string | undefined,
  redirects: [] as string[],
  currentUser: { userId: "user-1" } as unknown,
  currentUserError: undefined as unknown,
}));

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      sessionState.cookie === undefined ? undefined : { name, value: sessionState.cookie },
  }),
}));

vi.mock("next/navigation", () => ({
  redirect: (path: string) => {
    sessionState.redirects.push(path);
    const error = new Error(`NEXT_REDIRECT:${path}`) as Error & { digest?: string };
    error.digest = `NEXT_REDIRECT;replace;${path};307;`;
    throw error;
  },
}));

vi.mock("@/lib/api/server/server-queries", () => ({
  serverQueries: {
    getCurrentUser: async () => {
      if (sessionState.currentUserError !== undefined) throw sessionState.currentUserError;
      return sessionState.currentUser;
    },
  },
}));

import {
  SESSION_EXPIRED_LOGIN_PATH,
  getSessionCookie,
  requireSession,
  requireSessionUser,
  withActiveSession,
} from "./server-session";

afterEach(() => {
  sessionState.cookie = undefined;
  sessionState.redirects = [];
  sessionState.currentUser = { userId: "user-1" };
  sessionState.currentUserError = undefined;
});

describe("requireSession", () => {
  it("sends a visitor without a session cookie to the expired-session login page", async () => {
    await expect(requireSession()).rejects.toThrow("NEXT_REDIRECT");
    expect(sessionState.redirects).toEqual([SESSION_EXPIRED_LOGIN_PATH]);
    expect(SESSION_EXPIRED_LOGIN_PATH).toBe("/login?reason=session-expired");
  });

  it("keeps rendering when the session cookie is present", async () => {
    sessionState.cookie = "session-token";
    await expect(requireSession()).resolves.toBeUndefined();
    expect(sessionState.redirects).toEqual([]);
  });
});

describe("withActiveSession", () => {
  it("returns the value produced by the wrapped query", async () => {
    await expect(withActiveSession(async () => "ok")).resolves.toBe("ok");
    expect(sessionState.redirects).toEqual([]);
  });

  it("redirects to the login page when the backend reports an unauthorized session", async () => {
    const unauthorized = { kind: "unauthorized", message: "登录状态已失效。" };

    await expect(withActiveSession(async () => {
      throw unauthorized;
    })).rejects.toThrow("NEXT_REDIRECT");
    expect(sessionState.redirects).toEqual([SESSION_EXPIRED_LOGIN_PATH]);
  });

  it("rethrows non-unauthorized failures so the route error boundary still reports them", async () => {
    const failure = { kind: "server_error", message: "上游服务不可用。" };

    await expect(withActiveSession(async () => {
      throw failure;
    })).rejects.toBe(failure);
    expect(sessionState.redirects).toEqual([]);
  });
});

describe("requireSessionUser", () => {
  it("returns the current user while the session is alive", async () => {
    sessionState.cookie = "session-token";
    await expect(requireSessionUser()).resolves.toEqual({ userId: "user-1" });
  });

  it("redirects instead of surfacing the backend 401 when the session expired", async () => {
    sessionState.cookie = "session-token";
    sessionState.currentUserError = { kind: "unauthorized", message: "登录状态已失效。" };

    await expect(requireSessionUser()).rejects.toThrow("NEXT_REDIRECT");
    expect(sessionState.redirects).toEqual([SESSION_EXPIRED_LOGIN_PATH]);
  });
});

describe("getSessionCookie", () => {
  it("reads the unified portal session cookie value", async () => {
    sessionState.cookie = "session-token";
    await expect(getSessionCookie()).resolves.toBe("session-token");
  });
});
