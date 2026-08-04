import type { ReactNode } from "react";
import { DashboardShell } from "@/components/layouts/dashboard-shell";
import { serverQueries } from "@/lib/api/server/server-queries";

export default async function AccountLayout({ children }: { children: ReactNode }) {
  const currentUser = await serverQueries.getCurrentUser();
  return <DashboardShell mode="account" currentUser={currentUser}>{children}</DashboardShell>;
}
