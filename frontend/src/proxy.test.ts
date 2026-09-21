//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-14
// Description: Pre-render administration-console access gate tests
//

import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { unstable_doesMiddlewareMatch } from "next/experimental/testing/server";
import { FULL_PERMISSIONS, NO_PERMISSIONS } from "@/types/permissions";
import { config, proxy } from "@/proxy";

function pageRequest(withSession = true, pathname = "/admin/users"): NextRequest {
  return new NextRequest(`https://portal.example${pathname}`, {
    headers: withSession ? { Cookie: "up_session=session-token" } : undefined,
  });
}

function expectSecurityHeaders(response: Response): string {
  const policy = response.headers.get("content-security-policy");
  expect(policy).toBeTruthy();
  expect(policy).not.toContain("'unsafe-eval'");
  expect(policy).toContain("script-src 'self' 'nonce-");
  expect(policy).toContain("'strict-dynamic'");
  expect(policy).toContain("frame-ancestors 'none'");
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  expect(response.headers.get("x-frame-options")).toBe("DENY");
  expect(response.headers.get("permissions-policy")).toContain("camera=()");

  const nonce = policy?.match(/'nonce-([^']+)'/u)?.[1];
  expect(nonce).toMatch(/^[0-9a-f]{32}$/u);
  return nonce ?? "";
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("administration proxy", () => {
  it("matches documents while excluding API and framework asset paths", () => {
    const matches = (url: string, accept?: string) => unstable_doesMiddlewareMatch({
      config,
      nextConfig: {},
      url,
      headers: accept ? { accept } : undefined,
    });

    expect(matches("/privacy")).toBe(true);
    expect(matches("/login", "application/json")).toBe(true);
    expect(matches("/login", "*/*")).toBe(true);
    expect(matches("/terms")).toBe(true);
    expect(matches("/admin/users")).toBe(true);
    expect(matches("/admin/users", "application/json")).toBe(true);
    expect(matches("/admin/applications/client.example")).toBe(true);
    expect(matches("/api/v1/me")).toBe(false);
    expect(matches("/api")).toBe(false);
    expect(matches("/apiary")).toBe(true);
    expect(matches("/_next/static/chunks/app.js")).toBe(false);
    expect(matches("/_next/image?url=%2Ficon.png&w=32&q=75")).toBe(false);
    expect(matches("/_next")).toBe(true);
    expect(matches("/_next/staticity/not-found")).toBe(true);
    expect(matches("/favicon.ico")).toBe(false);
    expect(matches("/icon.png")).toBe(false);
    expect(matches("/brand/gravel-evolution-logo.png")).toBe(false);
    expect(matches("/brand/auth-carousel-2-v2.jpg")).toBe(false);
    expect(matches("/brand/missing.v2", "application/json")).toBe(true);
    expect(matches("/up-automation-cost-worker.js")).toBe(false);
    expect(matches("/file.svg")).toBe(false);
    expect(matches("/missing/document.v2", "text/html,application/xhtml+xml")).toBe(true);
    expect(matches("/missing/document.v2", "application/json")).toBe(true);
  });

  it("redirects an unauthenticated dotted administration path", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const response = await proxy(pageRequest(false, "/admin/applications/client.example"));

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe("https://portal.example/login");
    expectSecurityHeaders(response);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("adds a unique nonce and security headers to public pages without an authorization fetch", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const first = await proxy(pageRequest(false, "/privacy"));
    const second = await proxy(pageRequest(false, "/terms"));

    expect(first.headers.get("x-middleware-next")).toBe("1");
    expect(second.headers.get("x-middleware-next")).toBe("1");
    expect(expectSecurityHeaders(first)).not.toBe(expectSecurityHeaders(second));
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("redirects a request without a session before fetching permissions", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const response = await proxy(pageRequest(false));

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe("https://portal.example/login");
    expectSecurityHeaders(response);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("redirects an external user before the administration route renders", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json(NO_PERMISSIONS));
    const response = await proxy(pageRequest());

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe("https://portal.example/account");
    expectSecurityHeaders(response);
  });

  it("allows a user with administration capabilities", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json(FULL_PERMISSIONS));
    const response = await proxy(pageRequest());

    expect(response.status).toBe(200);
    expect(response.headers.get("x-middleware-next")).toBe("1");
    expectSecurityHeaders(response);
  });

  it("checks DreamUP event authorization directly for its management surface", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({
      events: [{ eventId: "dreamup-shanghai-2026", displayName: "上海站" }],
    }));
    const response = await proxy(pageRequest(true, "/admin/dreamup"));

    expect(response.status).toBe(200);
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain("/admin/dreamup/events");
  });

  it("returns a clear 403 for a signed-in user without DreamUP event access", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json(
      { error: { message: "forbidden" } },
      { status: 403 },
    ));
    const response = await proxy(pageRequest(true, "/admin/dreamup"));

    expect(response.status).toBe(403);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expectSecurityHeaders(response);
  });

  it("fails closed when the permission service response is malformed", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ userRead: true }));
    const response = await proxy(pageRequest());

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expectSecurityHeaders(response);
  });
});
