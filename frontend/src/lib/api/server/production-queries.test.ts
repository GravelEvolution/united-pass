//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Real HTTP contract tests for final production server queries
//

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("next/headers", () => ({
  cookies: async () => ({ get: () => ({ name: "up_session", value: "session" }) }),
  headers: async () => ({ get: () => null }),
}));

import { serverQueries } from "./server-queries";

type FetchCall = { url: string; init: RequestInit };

function stubFetch(value: unknown): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(value), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }));
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe("final production server queries", () => {
  it("loads and narrows the independently permission-scoped dashboard", async () => {
    const calls = stubFetch({
      metrics: [{ label: "活跃用户", value: "12", change: "1 个待激活", tone: "attention" }],
      recentEvents: [{
        eventId: "evt_1", eventType: "session.revoked", actorName: "Admin",
        actorId: "user_admin", targetLabel: "Session", targetId: "session_1",
        occurredAt: "2026-08-16T00:00:00Z", result: "success",
        requestId: "req_1", details: "",
      }],
    });

    await expect(serverQueries.getAdminDashboard()).resolves.toMatchObject({
      metrics: [{ value: "12", tone: "attention" }],
      recentEvents: [{ eventId: "evt_1" }],
    });
    expect(calls[0].url).toBe("http://localhost:8080/api/v1/admin/dashboard");
    expect(calls[0].init.cache).toBe("no-store");
  });

  it("loads the authoritative OAuth scope catalog from the backend", async () => {
    const calls = stubFetch([{
      scope: "openid", label: "OpenID", description: "OIDC identity", required: false,
    }]);

    await expect(serverQueries.getAvailableScopes()).resolves.toEqual([{
      scope: "openid", label: "OpenID", description: "OIDC identity", required: false,
    }]);
    expect(calls[0].url).toBe("http://localhost:8080/api/v1/admin/scopes");
  });
});
