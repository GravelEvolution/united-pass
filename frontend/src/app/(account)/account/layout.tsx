import type { ReactNode } from "react";
import { DashboardShell } from "@/components/layouts/dashboard-shell";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export default async function AccountLayout({ children }: { children: ReactNode }) {
  const currentUser = await mockUnitedPassDataSource.getCurrentUser();
  return <DashboardShell mode="account" currentUser={currentUser}>{children}</DashboardShell>;
}
