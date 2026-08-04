import type { Metadata } from "next";
import { EmployeesTable } from "@/features/admin/components/tables/employees-table";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "员工管理" };
export default async function EmployeesPage() { return <EmployeesTable records={await mockUnitedPassDataSource.getEmployees()} />; }
