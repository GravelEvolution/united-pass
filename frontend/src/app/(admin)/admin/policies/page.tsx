//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Admin page: policy listing
//

import type { Metadata } from "next";
import { PoliciesTable } from "@/features/admin/components/tables/policies-table";
import { serverQueries } from "@/lib/api/server/server-queries";
import type { PageQuery } from "@/types/pagination";

export const metadata: Metadata = { title: "授权策略" };
export const dynamic = "force-dynamic";

export default async function PoliciesPage({
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
  const page = await serverQueries.getPolicies(query);
  return <PoliciesTable records={page.items} actionHref="/admin/policies/new" />;
}
