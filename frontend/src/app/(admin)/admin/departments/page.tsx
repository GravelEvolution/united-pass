import type { Metadata } from "next";
import { DepartmentsTable } from "@/features/admin/components/tables/departments-table";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "部门管理" };
export default async function DepartmentsPage() { return <DepartmentsTable records={await serverQueries.getDepartments()} />; }
