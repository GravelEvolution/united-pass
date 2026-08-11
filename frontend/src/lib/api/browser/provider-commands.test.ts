//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 6 Provider browser mutation contract tests
//

import { afterEach, describe, expect, it, vi } from "vitest";
import { browserCommands } from "./browser-commands";

type FetchCall = { url: string; init: RequestInit };

function stubFetch(response: Response): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal("document", { cookie: "up_csrf=csrf-value" });
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return response;
  }));
  return calls;
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function headerOf(call: FetchCall, name: string): string | null {
  return new Headers(call.init.headers as HeadersInit).get(name);
}

afterEach(() => vi.unstubAllGlobals());

describe("P6 Provider browser commands", () => {
  const provider = {
    providerId: "provider_feishu", displayName: "飞书", vendor: "feishu",
    integrationLabel: "OAuth 2.0 + 通讯录 OpenAPI", status: "active",
    loginEnabled: true, linkedUserCount: 0, updatedAt: "2026-08-11T00:00:00Z",
    appId: "cli_test", secretConfigured: true,
    callbackUrl: "https://id.example.test/api/v1/auth/providers/feishu/callback",
    contactScope: "contact:user.base:readonly", lastValidatedAt: null,
    lastSyncAt: null, lastSyncResult: null,
  };

  it("uses an exact target-bound grant for Provider enablement", async () => {
    const calls = stubFetch(jsonResponse(provider));
    await browserCommands.updateProviderLogin("provider/feishu", true, "provider-grant");
    expect(calls[0].url).toBe("/api/v1/admin/identity-providers/provider%2Ffeishu/enable");
    expect(calls[0].init.method).toBe("POST");
    expect(headerOf(calls[0], "X-Reauthentication-Token")).toBe("provider-grant");
    expect(headerOf(calls[0], "X-CSRF-Token")).toBe("csrf-value");
  });

  it("queues a durable sync and parses its 202 representation", async () => {
    const job = {
      syncId: "sync_A", providerId: "provider_feishu",
      startedAt: "2026-08-11T00:00:00Z", completedAt: null, status: "pending",
      departmentsAdded: 0, departmentsUpdated: 0, employeesAdded: 0,
      employeesUpdated: 0, employeesOffboarded: 0, conflictsDetected: 0,
    };
    const calls = stubFetch(jsonResponse(job, 202));
    await expect(browserCommands.syncProviderDirectory("provider_feishu")).resolves.toMatchObject({
      syncId: "sync_A", status: "pending", completedAt: null,
    });
    expect(calls[0].url).toBe("/api/v1/admin/identity-providers/provider_feishu/directory-syncs");
  });

  it("passes the selected stable user ID only through explicit conflict resolution", async () => {
    const calls = stubFetch(new Response(null, { status: 204 }));
    await browserCommands.resolveSyncConflict("conflict/A", "user_A", "link-grant");
    expect(calls[0].url).toBe("/api/v1/admin/identity-providers/sync-conflicts/conflict%2FA/resolve");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ userId: "user_A" });
    expect(headerOf(calls[0], "X-Reauthentication-Token")).toBe("link-grant");
  });
});
