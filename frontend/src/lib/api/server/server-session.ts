import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { SESSION_COOKIE_NAME } from "@/lib/api/constants";

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

export async function getSessionCookie(): Promise<string | undefined> {
  const cookieStore = await cookies();
  return cookieStore.get(SESSION_COOKIE_NAME)?.value;
}

export async function requireSession(): Promise<void> {
  const session = await getSessionCookie();
  if (!session) {
    redirect("/login");
  }
}
