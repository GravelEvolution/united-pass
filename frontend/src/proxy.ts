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

function redirectTo(request: NextRequest, pathname: string): NextResponse {
  return NextResponse.redirect(new URL(pathname, request.url));
}

function unavailable(): NextResponse {
  return new NextResponse("管理后台暂时不可用。", {
    status: 503,
    headers: { "Cache-Control": "no-store" },
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

  let response: Response;
  try {
    response = await fetch(`${SERVER_API_BASE_URL}/me/permissions`, {
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
  if (!response.ok) {
    return unavailable();
  }

  let permissions: unknown;
  try {
    permissions = await response.json();
  } catch {
    return unavailable();
  }
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
