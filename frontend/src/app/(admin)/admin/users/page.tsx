import type { Metadata } from "next";
import { ManagementDirectory } from "@/features/admin/components/management-directory";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "用户管理" };
export default async function UsersPage() { return <ManagementDirectory kind="users" records={await mockUnitedPassDataSource.getUsers()} />; }
