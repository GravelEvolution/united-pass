import type { ReactNode } from "react";
import { DashboardShell } from "@/components/layouts/dashboard-shell";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export default async function AdminLayout({ children }: { children: ReactNode }) {
  const currentUser = await mockUnitedPassDataSource.getCurrentUser();
  return <DashboardShell mode="admin" currentUser={currentUser}>{children}</DashboardShell>;
}
