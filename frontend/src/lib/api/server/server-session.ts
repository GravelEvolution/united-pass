//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Server-side session access helpers
//

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { isApiError } from "@/lib/api/api-error";
import { SESSION_COOKIE_NAME } from "@/lib/api/constants";
import { serverQueries } from "@/lib/api/server/server-queries";
import type { CurrentUser } from "@/types/identity";

/**
 * Server-side session reading.
 *
 * Reads the `up_session` HttpOnly cookie via `next/headers` cookies()
 * and forwards it to the backend API as a Cookie header.
 *
 * See ADR-0004 for the API client architecture.
 * See ADR-0006 for the Cookie naming and deployment topology.
 */

export { SESSION_COOKIE_NAME };

export const SESSION_EXPIRED_LOGIN_PATH = "/login?reason=session-expired";

export async function getSessionCookie(): Promise<string | undefined> {
  const cookieStore = await cookies();
  return cookieStore.get(SESSION_COOKIE_NAME)?.value;
}

export async function requireSession(): Promise<void> {
  const session = await getSessionCookie();
  if (!session) {
    redirect(SESSION_EXPIRED_LOGIN_PATH);
  }
}

export async function withActiveSession<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (isApiError(error) && error.kind === "unauthorized") {
      redirect(SESSION_EXPIRED_LOGIN_PATH);
    }
    throw error;
  }
}

export async function requireSessionUser(): Promise<CurrentUser> {
  await requireSession();
  return withActiveSession(() => serverQueries.getCurrentUser());
}
