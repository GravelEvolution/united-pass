import { cookies } from "next/headers";
import { redirect } from "next/navigation";

/**
 * Server-side session reading.
 *
 * When the real backend API is available, this module will:
 * - Read the session cookie via `next/headers` cookies()
 * - Optionally validate the session by calling a backend endpoint
 * - Provide helpers for requiring authentication before page render
 *
 * See ADR-0004 for the full architecture.
 *
 * This file is currently a stub. The mock data source handles session
 * state directly until the backend is available.
 */

export const SESSION_COOKIE_NAME = "session";

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
