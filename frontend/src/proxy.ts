//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-14
// Description: Pre-render administration-console access gate
//

import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import {
  SERVER_API_BASE_URL,
  SESSION_COOKIE_NAME,
} from "@/lib/api/constants";
import {
  canAccessAdminConsole,
  isPermissionCapabilities,
} from "@/types/permissions";
import { parseDreamUPEvents } from "@/features/dreamup-admin/api/response-validators";
import { hasDreamUPAdministrationAccess } from "@/features/dreamup-admin/permissions";
import {
  createContentSecurityPolicy,
  createDocumentSecurityHeaders,
  type ApplicationEnvironment,
} from "@/lib/security/content-security-policy";
import { USE_MOCK_DATA_SOURCE } from "@/lib/api/data-source-mode";

function applicationEnvironment(): ApplicationEnvironment {
  return process.env.NODE_ENV;
}

function createNonce(): string {
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(randomBytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function isAdministrationPath(pathname: string): boolean {
  return pathname === "/admin" || pathname.startsWith("/admin/");
}

function nextWithSecurityContext(
  request: NextRequest,
  nonce: string,
  contentSecurityPolicy: string,
): NextResponse {
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", contentSecurityPolicy);
  return NextResponse.next({ request: { headers: requestHeaders } });
}

function secureResponse(
  response: NextResponse,
  contentSecurityPolicy: string,
  environment: ApplicationEnvironment,
): NextResponse {
  for (const [name, value] of createDocumentSecurityHeaders(contentSecurityPolicy, environment)) {
    response.headers.set(name, value);
  }
  return response;
}
function redirectTo(request: NextRequest, pathname: string): NextResponse {
  return NextResponse.redirect(new URL(pathname, request.url));
}

function unavailable(): NextResponse {
  return new NextResponse("管理后台暂时不可用。", {
    status: 503,
    headers: { "Cache-Control": "no-store" },
  });
}

function forbidden(): NextResponse {
  return new NextResponse("你没有 MoonStone DreamUP 活动管理权限。", {
    status: 403,
    headers: { "Cache-Control": "no-store", "Content-Type": "text/plain; charset=utf-8" },
  });
}

/**
 * Prevents an unauthorized administration page from starting React streaming.
 * Backend handlers remain the authoritative security boundary for every API.
 */
export async function proxy(request: NextRequest): Promise<NextResponse> {
  const environment = applicationEnvironment();
  const nonce = createNonce();
  const contentSecurityPolicy = createContentSecurityPolicy(nonce, environment);
  const finish = (response: NextResponse) => secureResponse(
    response,
    contentSecurityPolicy,
    environment,
  );

  if (!isAdministrationPath(request.nextUrl.pathname)) {
    return finish(nextWithSecurityContext(request, nonce, contentSecurityPolicy));
  }

  const session = request.cookies.get(SESSION_COOKIE_NAME);
  if (!session) {
    return finish(redirectTo(request, "/login"));
  }

  if (USE_MOCK_DATA_SOURCE) {
    return finish(nextWithSecurityContext(request, nonce, contentSecurityPolicy));
  }

  const headers = new Headers({
    Cookie: `${SESSION_COOKIE_NAME}=${session.value}`,
  });
  const requestId = request.headers.get("x-request-id");
  if (requestId) headers.set("X-Request-ID", requestId);

  const isDreamUPAdministration = request.nextUrl.pathname === "/admin/dreamup"
    || request.nextUrl.pathname.startsWith("/admin/dreamup/");
  const authorizationPath = isDreamUPAdministration
    ? "/admin/dreamup/events"
    : "/me/permissions";

  let response: Response;
  try {
    response = await fetch(`${SERVER_API_BASE_URL}${authorizationPath}`, {
      headers,
      cache: "no-store",
      signal: request.signal,
    });
  } catch {
    return finish(unavailable());
  }

  if (response.status === 401) {
    return finish(redirectTo(request, "/login"));
  }
  if (isDreamUPAdministration && (response.status === 403 || response.status === 404)) {
    return finish(forbidden());
  }
  if (!response.ok) {
    return finish(unavailable());
  }

  let authorization: unknown;
  try {
    authorization = await response.json();
  } catch {
    return finish(unavailable());
  }
  if (isDreamUPAdministration) {
    try {
      return finish(hasDreamUPAdministrationAccess(parseDreamUPEvents(authorization))
        ? nextWithSecurityContext(request, nonce, contentSecurityPolicy)
        : forbidden());
    } catch {
      return finish(unavailable());
    }
  }
  const permissions = authorization;
  if (!isPermissionCapabilities(permissions)) {
    return finish(unavailable());
  }
  if (!canAccessAdminConsole(permissions)) {
    return finish(redirectTo(request, "/account"));
  }

  return finish(nextWithSecurityContext(request, nonce, contentSecurityPolicy));
}

export const config = {
  matcher: [
    // Administration is security-gated regardless of filename-like dots or
    // request headers. Keep this entry before the document matcher.
    "/admin/:path*",
    // Match application documents regardless of the caller-controlled Accept
    // header. Only exact API/framework asset boundaries and reviewed public
    // files are excluded. Unknown dotted or asset-lookalike paths intentionally
    // receive the HTML 404 policy instead of inheriting a broad prefix bypass.
    "/((?!api(?:/|$)|_next/(?:static|image)(?:/|$)|favicon\\.ico$|sitemap\\.xml$|robots\\.txt$|icon\\.png$|brand/(?:auth-carousel-1\\.jpg|auth-carousel-2-v2\\.jpg|auth-carousel-3\\.jpg|gravel-evolution-logo\\.png)$|up-automation-cost-worker\\.js$|(?:file|globe|next|vercel|window)\\.svg$).*)",
  ],
};
