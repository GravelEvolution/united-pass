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
  const session = request.cookies.get(SESSION_COOKIE_NAME);
  if (!session) {
    return redirectTo(request, "/login");
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
    return unavailable();
  }

  if (response.status === 401) {
    return redirectTo(request, "/login");
  }
  if (isDreamUPAdministration && (response.status === 403 || response.status === 404)) {
    return forbidden();
  }
  if (!response.ok) {
    return unavailable();
  }

  let authorization: unknown;
  try {
    authorization = await response.json();
  } catch {
    return unavailable();
  }
  if (isDreamUPAdministration) {
    try {
      return hasDreamUPAdministrationAccess(parseDreamUPEvents(authorization))
        ? NextResponse.next()
        : forbidden();
    } catch {
      return unavailable();
    }
  }
  const permissions = authorization;
  if (!isPermissionCapabilities(permissions)) {
    return unavailable();
  }
  if (!canAccessAdminConsole(permissions)) {
    return redirectTo(request, "/account");
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/admin/:path*"],
};
