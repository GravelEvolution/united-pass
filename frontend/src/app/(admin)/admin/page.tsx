import type { Metadata } from "next";
import { AdminOverview } from "@/features/admin/components/admin-overview";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "管理工作台" };

export default async function AdminPage() {
  const dashboard = await mockUnitedPassDataSource.getAdminDashboard();
  return <AdminOverview dashboard={dashboard} />;
}
