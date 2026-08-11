//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Admin page: department listing
//

import type { Metadata } from "next";
import { DepartmentsTable } from "@/features/admin/components/tables/departments-table";
import { DepartmentCreateButton } from "@/features/admin/components/department-actions";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "部门管理" };
export const dynamic = "force-dynamic";

export default async function DepartmentsPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const params = await searchParams;
  const [records, allDepartments, employeesPage, permissions] = await Promise.all([
    serverQueries.getDepartments({ query: params.q, limit: 100 }),
    serverQueries.getDepartments({ limit: 100 }),
    serverQueries.getEmployees({ limit: 20, status: "active", sort: "displayName" }),
    serverQueries.getCurrentPermissions(),
  ]);
  const action = permissions.departmentManage ? (
    <DepartmentCreateButton departments={allDepartments} employees={employeesPage.items} />
  ) : undefined;
  return <DepartmentsTable records={records} query={params.q} action={action} />;
}
