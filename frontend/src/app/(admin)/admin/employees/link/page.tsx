import type { Metadata } from "next";
import { EmployeeLinkForm } from "@/features/admin/components/employee-link-form";
import { serverQueries } from "@/lib/api/server/server-queries";
import type { PageQuery } from "@/types/pagination";

export const metadata: Metadata = { title: "关联员工档案" };
export const dynamic = "force-dynamic";

export default async function EmployeeLinkPage() {
  const query: PageQuery = { limit: 100 };
  const [usersPage, departments] = await Promise.all([
    serverQueries.getUsers(query),
    serverQueries.getDepartments(),
  ]);

  return <EmployeeLinkForm users={usersPage.items} departments={departments} />;
}
