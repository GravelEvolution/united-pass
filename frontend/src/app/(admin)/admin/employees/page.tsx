import type { Metadata } from "next";
import { EmployeesTable } from "@/features/admin/components/tables/employees-table";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "员工管理" };
export default async function EmployeesPage() { return <EmployeesTable records={await serverQueries.getEmployees()} />; }
