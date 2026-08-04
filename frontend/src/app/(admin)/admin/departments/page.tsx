import type { Metadata } from "next";
import { ManagementDirectory } from "@/features/admin/components/management-directory";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "部门管理" };
export default async function DepartmentsPage() { return <ManagementDirectory kind="departments" records={await mockUnitedPassDataSource.getDepartments()} />; }
