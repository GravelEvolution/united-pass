import type { Metadata } from "next";
import { UsersTable } from "@/features/admin/components/tables/users-table";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "用户管理" };
export default async function UsersPage() { return <UsersTable records={await mockUnitedPassDataSource.getUsers()} />; }
