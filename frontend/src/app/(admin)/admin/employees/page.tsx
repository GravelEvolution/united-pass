import type { Metadata } from "next";
import { EmployeesTable } from "@/features/admin/components/tables/employees-table";
import { serverQueries } from "@/lib/api/server/server-queries";
import type { PageQuery } from "@/types/pagination";

export const metadata: Metadata = { title: "员工管理" };
export const dynamic = "force-dynamic";

export default async function EmployeesPage({
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
  const page = await serverQueries.getEmployees(query);
  return <EmployeesTable records={page.items} />;
}
