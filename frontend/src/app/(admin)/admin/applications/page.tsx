import type { Metadata } from "next";
import { ApplicationsTable } from "@/features/admin/components/tables/applications-table";
import { serverQueries } from "@/lib/api/server/server-queries";
import type { PageQuery } from "@/types/pagination";

export const metadata: Metadata = { title: "OAuth 应用" };
export const dynamic = "force-dynamic";

export default async function ApplicationsPage({
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
  const page = await serverQueries.getApplications(query);
  return <ApplicationsTable records={page.items} />;
}
