//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 7 policy and audit browser command contract tests
//

import { afterEach, describe, expect, it, vi } from "vitest";
import { browserCommands } from "./browser-commands";

type FetchCall = { url: string; init: RequestInit };

function stubFetch(responses: Response[]): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal("document", { cookie: "up_csrf=csrf-value" });
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const response = responses.shift();
    if (!response) throw new Error("unexpected fetch");
    return response;
  }));
  return calls;
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}

function header(call: FetchCall, name: string): string | null {
  return new Headers(call.init.headers as HeadersInit).get(name);
}

afterEach(() => vi.unstubAllGlobals());

describe("P7 policy and audit browser commands", () => {
  it("PATCHes an exact expected policy version and publishes with step-up", async () => {
    const calls = stubFetch([
      jsonResponse({ policyId: "pol_1", version: 4 }),
      jsonResponse({ version: 4 }),
    ]);
    const saved = await browserCommands.savePolicyDraft({
      policyId: "pol/1", expectedVersion: 3, name: "策略", description: "",
      resource: "application:*", action: "application.manage", effect: "allow",
      principals: [], conditions: [],
    });
    await browserCommands.publishPolicy(saved.policyId, saved.version, "publish-grant");
    expect(calls[0].url).toBe("/api/v1/admin/policies/pol%2F1");
    expect(JSON.parse(String(calls[0].init.body)).expectedVersion).toBe(3);
    expect(calls[1].url).toBe("/api/v1/admin/policies/pol_1/publish");
    expect(JSON.parse(String(calls[1].init.body))).toEqual({ version: 4 });
    expect(header(calls[1], "X-Reauthentication-Token")).toBe("publish-grant");
    expect(header(calls[1], "X-CSRF-Token")).toBe("csrf-value");
  });

  it("creates and polls an asynchronous audit export without inventing completion", async () => {
    const pending = {
      exportId: "exp_1", status: "pending", downloadUrl: null,
      requestedAt: "2026-08-11T00:00:00Z", completedAt: null, totalEvents: 0,
    };
    const calls = stubFetch([
      jsonResponse(pending, 202),
      jsonResponse({ ...pending, status: "completed", downloadUrl: "/api/v1/admin/audit-exports/exp_1/download", completedAt: "2026-08-11T00:00:01Z", totalEvents: 2 }),
    ]);
    const created = await browserCommands.exportAuditEvents({ result: "denied" }, "export-grant");
    expect(created.status).toBe("pending");
    const completed = await browserCommands.getAuditExport(created.exportId);
    expect(completed.status).toBe("completed");
    expect(calls[0].url).toBe("/api/v1/admin/audit-exports");
    expect(header(calls[0], "X-Reauthentication-Token")).toBe("export-grant");
    expect(calls[1].init.method ?? "GET").toBe("GET");
  });
});
