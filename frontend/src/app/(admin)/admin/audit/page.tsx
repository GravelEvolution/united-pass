//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Admin page: security audit explorer
//

import type { Metadata } from "next";
import { AuditExplorer } from "@/features/admin/components/audit-explorer";
import { serverQueries } from "@/lib/api/server/server-queries";
import type { AuditQuery } from "@/features/admin/types";

export const metadata: Metadata = { title: "审计事件" };
export const dynamic = "force-dynamic";

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{
    q?: string;
    eventType?: string;
    result?: string;
    actorName?: string;
    requestId?: string;
    from?: string;
    to?: string;
    cursor?: string;
  }>;
}) {
  const params = await searchParams;
  const query: AuditQuery = {
    query: params.q,
    eventType: params.eventType,
    result: params.result,
    actorName: params.actorName,
    requestId: params.requestId,
    from: params.from,
    to: params.to,
    cursor: params.cursor,
  };
  const page = await serverQueries.getAuditEvents(query);
  return <AuditExplorer records={page.items} />;
}
