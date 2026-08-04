import type { Metadata } from "next";
import { DepartmentsTable } from "@/features/admin/components/tables/departments-table";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "部门管理" };
export const dynamic = "force-dynamic";

export default async function DepartmentsPage() {
  const records = await serverQueries.getDepartments();
  return <DepartmentsTable records={records} />;
}
