import type { Metadata } from "next";
import { UsersTable } from "@/features/admin/components/tables/users-table";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "用户管理" };
export default async function UsersPage() { return <UsersTable records={await serverQueries.getUsers()} />; }
