//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 5 browser mutation contract tests
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

function bodyOf(call: FetchCall): Record<string, unknown> {
  return JSON.parse(String(call.init.body)) as Record<string, unknown>;
}

function headerOf(call: FetchCall, name: string): string | null {
  return new Headers(call.init.headers as HeadersInit).get(name);
}

afterEach(() => vi.unstubAllGlobals());

describe("P5 workforce browser commands", () => {
  it("requests a grant bound only to the exact target user", async () => {
    const calls = stubFetch(jsonResponse({
      status: "granted",
      reauthToken: "grant",
      expiresAt: "2026-08-11T01:00:00Z",
    }));
    await browserCommands.requestReauthentication({
      action: "employee.offboard",
      target: "user/target",
      password: "current-password",
    });
    expect(bodyOf(calls[0])).toEqual({
      action: "employee.offboard",
      applicationId: "",
      clientId: "",
      target: "user/target",
      password: "current-password",
    });
  });

  it("binds disable and bulk revoke to the constrained grant header", async () => {
    let calls = stubFetch(new Response(null, { status: 204 }));
    await browserCommands.updateUserStatus("user/target", "disabled", "disable-grant");
    expect(calls[0].url).toBe("/api/v1/admin/users/user%2Ftarget/disable");
    expect(bodyOf(calls[0])).toEqual({ revokeSessions: true });
    expect(headerOf(calls[0], "X-Reauthentication-Token")).toBe("disable-grant");
    expect(headerOf(calls[0], "X-CSRF-Token")).toBe("csrf-value");

    vi.unstubAllGlobals();
    calls = stubFetch(new Response(null, { status: 204 }));
    await browserCommands.revokeUserSessions("user/target", "sessions-grant");
    expect(calls[0].url).toBe("/api/v1/admin/users/user%2Ftarget/sessions");
    expect(headerOf(calls[0], "X-Reauthentication-Token")).toBe("sessions-grant");
  });

  it("keeps enable and one-session revoke outside the reauthentication seam", async () => {
    let calls = stubFetch(new Response(null, { status: 204 }));
    await browserCommands.updateUserStatus("user_A", "active");
    expect(calls[0].url).toBe("/api/v1/admin/users/user_A/enable");
    expect(headerOf(calls[0], "X-Reauthentication-Token")).toBeNull();

    vi.unstubAllGlobals();
    calls = stubFetch(new Response(null, { status: 204 }));
    await browserCommands.revokeUserSession("user_A", "session/other");
    expect(calls[0].url).toBe("/api/v1/admin/users/user_A/sessions/session%2Fother");
    expect(headerOf(calls[0], "X-Reauthentication-Token")).toBeNull();
  });

  it("uses explicit stable IDs for employee link, update and offboarding", async () => {
    let calls = stubFetch(jsonResponse({ userId: "user_A" }, 201));
    await browserCommands.linkEmployeeProfile({
      userId: "user_A",
      departmentId: "dep_A",
      title: "Engineer",
      supervisorUserId: "user_B",
    });
    expect(calls[0].url).toBe("/api/v1/admin/employees/link");
    expect(bodyOf(calls[0])).toEqual({
      userId: "user_A",
      departmentId: "dep_A",
      title: "Engineer",
      supervisorUserId: "user_B",
    });

    vi.unstubAllGlobals();
    calls = stubFetch(jsonResponse({ userId: "user_A" }));
    await browserCommands.updateEmployeeProfile("user_A", {
      departmentId: "dep_B",
      title: "Senior Engineer",
    });
    expect(calls[0].url).toBe("/api/v1/admin/users/user_A/employee-profile");
    expect(calls[0].init.method).toBe("PUT");

    vi.unstubAllGlobals();
    calls = stubFetch(jsonResponse({ status: "offboarding", sessionCleanupPending: true }, 202));
    await browserCommands.offboardEmployee("user_A", "offboard-grant");
    expect(calls[0].url).toBe("/api/v1/admin/users/user_A/offboarding");
    expect(headerOf(calls[0], "X-Reauthentication-Token")).toBe("offboard-grant");
  });

  it("parses department mutations and deletes the exact department", async () => {
    const detail = {
      departmentId: "dep_A", name: "Platform", parentDepartmentId: null,
      parentName: null, ownerUserId: null, ownerName: "", memberCount: 0,
      childDepartments: [], members: [],
    };
    let calls = stubFetch(jsonResponse(detail, 201));
    await expect(browserCommands.createDepartment({ name: "Platform" })).resolves.toEqual(detail);
    expect(calls[0].url).toBe("/api/v1/admin/departments");

    vi.unstubAllGlobals();
    calls = stubFetch(jsonResponse({ ...detail, name: "Identity" }));
    await browserCommands.updateDepartment("dep_A", { name: "Identity", ownerUserId: null });
    expect(calls[0].url).toBe("/api/v1/admin/departments/dep_A");
    expect(calls[0].init.method).toBe("PATCH");

    vi.unstubAllGlobals();
    calls = stubFetch(new Response(null, { status: 204 }));
    await browserCommands.deleteDepartment("dep/A");
    expect(calls[0].url).toBe("/api/v1/admin/departments/dep%2FA");
  });
});
