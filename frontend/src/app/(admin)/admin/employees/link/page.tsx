//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Admin page: employee identity linking
//

import type { Metadata } from "next";
import { EmployeeLinkForm } from "@/features/admin/components/employee-link-form";
import { serverQueries } from "@/lib/api/server/server-queries";
import type { PageQuery } from "@/types/pagination";

export const metadata: Metadata = { title: "关联员工档案" };
export const dynamic = "force-dynamic";

export default async function EmployeeLinkPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const params = await searchParams;
  const query: PageQuery = { limit: 20, query: params.q, status: "active", sort: "displayName" };
  const [usersPage, departments, supervisorsPage] = await Promise.all([
    serverQueries.getUsers(query),
    serverQueries.getDepartments({ limit: 100 }),
    serverQueries.getEmployees({ limit: 20, status: "active", sort: "displayName" }),
  ]);

  return (
    <EmployeeLinkForm
      users={usersPage.items}
      departments={departments}
      supervisors={supervisorsPage.items}
      initialSearch={params.q ?? ""}
    />
  );
}
