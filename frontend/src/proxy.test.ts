//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-14
// Description: Pre-render administration-console access gate tests
//

import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { FULL_PERMISSIONS, NO_PERMISSIONS } from "@/types/permissions";
import { config, proxy } from "@/proxy";

function adminRequest(withSession = true): NextRequest {
  return new NextRequest("https://portal.example/admin/users", {
    headers: withSession ? { Cookie: "up_session=session-token" } : undefined,
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("administration proxy", () => {
  it("only matches administration routes", () => {
    expect(config.matcher).toEqual(["/admin/:path*"]);
  });

  it("redirects a request without a session before fetching permissions", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const response = await proxy(adminRequest(false));

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe("https://portal.example/login");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("redirects an external user before the administration route renders", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json(NO_PERMISSIONS));
    const response = await proxy(adminRequest());

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe("https://portal.example/account");
  });

  it("allows a user with administration capabilities", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json(FULL_PERMISSIONS));
    const response = await proxy(adminRequest());

    expect(response.status).toBe(200);
    expect(response.headers.get("x-middleware-next")).toBe("1");
  });

  it("fails closed when the permission service response is malformed", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ userRead: true }));
    const response = await proxy(adminRequest());

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});
