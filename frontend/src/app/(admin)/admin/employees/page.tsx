import type { Metadata } from "next";
import { ManagementDirectory } from "@/features/admin/components/management-directory";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "员工管理" };
export default async function EmployeesPage() { return <ManagementDirectory kind="employees" records={await mockUnitedPassDataSource.getEmployees()} />; }
