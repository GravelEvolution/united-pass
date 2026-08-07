//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Admin page: identity provider listing
//

import type { Metadata } from "next";
import { ProvidersTable } from "@/features/admin/components/tables/providers-table";
import { serverQueries } from "@/lib/api/server/server-queries";
import type { PageQuery } from "@/types/pagination";

export const metadata: Metadata = { title: "Provider 管理" };
export const dynamic = "force-dynamic";

export default async function ProvidersPage({
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
  const page = await serverQueries.getIdentityProviders(query);
  return <ProvidersTable records={page.items} />;
}
