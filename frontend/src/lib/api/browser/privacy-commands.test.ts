//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
// Date: 2026-08-11
// Description: Phase 8 privacy browser command contract tests
//

import { afterEach, describe, expect, it, vi } from "vitest";
import { browserCommands } from "./browser-commands";

type FetchCall = { url: string; init: RequestInit };

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}

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

afterEach(() => vi.unstubAllGlobals());

describe("P8 privacy browser commands", () => {
  it("creates and polls a requester-owned export with step-up", async () => {
    const pending = {
      exportId: "pexp_0123456789abcdef", status: "pending", requestedAt: "2026-08-11T00:00:00Z",
      completedAt: null, expiresAt: null, downloadUrl: null, totalSections: 0,
    };
    const calls = stubFetch([
      jsonResponse(pending, 202),
      jsonResponse({ ...pending, status: "completed", completedAt: "2026-08-11T00:00:01Z", expiresAt: "2026-08-11T00:15:01Z", totalSections: 6 }),
    ]);
    await browserCommands.requestPersonalDataExport("privacy-grant");
    await browserCommands.getPersonalDataExport(pending.exportId);
    expect(calls[0].url).toBe("/api/v1/me/data-exports");
    expect(new Headers(calls[0].init.headers).get("X-Reauthentication-Token")).toBe("privacy-grant");
    expect(calls[1].url).toContain(encodeURIComponent(pending.exportId));
  });

  it("requires step-up to request deletion but only CSRF to cancel during cooling", async () => {
    const deletion = {
      deletionId: "del_0123456789abcdef", status: "pending", requestedAt: "2026-08-11T00:00:00Z",
      executeAfter: "2026-09-10T00:00:00Z", cancelledAt: null, completedAt: null,
    };
    const calls = stubFetch([
      jsonResponse(deletion, 202),
      jsonResponse({ ...deletion, status: "cancelled", cancelledAt: "2026-08-11T00:01:00Z" }),
    ]);
    await browserCommands.requestAccountDeletion("delete-grant");
    await browserCommands.cancelAccountDeletion();
    expect(new Headers(calls[0].init.headers).get("X-Reauthentication-Token")).toBe("delete-grant");
    expect(calls[1].init.method).toBe("DELETE");
    expect(new Headers(calls[1].init.headers).get("X-CSRF-Token")).toBe("csrf-value");
    expect(new Headers(calls[1].init.headers).get("X-Reauthentication-Token")).toBeNull();
  });
});
