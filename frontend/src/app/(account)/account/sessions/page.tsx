//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Account page: active session management
//

import type { Metadata } from "next";
import { SessionList } from "@/features/account/components/session-list";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "活跃会话" };

export default async function SessionsPage() {
  const sessions = await serverQueries.getSessions();
  return <SessionList sessions={sessions} />;
}
