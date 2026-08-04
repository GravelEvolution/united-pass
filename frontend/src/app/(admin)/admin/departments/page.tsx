import type { Metadata } from "next";
import { DepartmentsTable } from "@/features/admin/components/tables/departments-table";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "部门管理" };
export default async function DepartmentsPage() { return <DepartmentsTable records={await mockUnitedPassDataSource.getDepartments()} />; }
