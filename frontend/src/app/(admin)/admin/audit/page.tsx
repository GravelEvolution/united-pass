import type { Metadata } from "next";
import { AuditTable } from "@/features/admin/components/tables/audit-table";
import { serverQueries } from "@/lib/api/server/server-queries";
import type { PageQuery } from "@/types/pagination";

export const metadata: Metadata = { title: "审计事件" };
export const dynamic = "force-dynamic";

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; status?: string; cursor?: string }>;
}) {
  const params = await searchParams;
  const query: PageQuery = {
    query: params.q,
    status: params.status,
    cursor: params.cursor,
  };
  const page = await serverQueries.getAuditEvents(query);
  return <AuditTable records={page.items} />;
}
