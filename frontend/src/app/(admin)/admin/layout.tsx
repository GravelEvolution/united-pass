import type { ReactNode } from "react";
import { DashboardShell } from "@/components/layouts/dashboard-shell";
import { serverQueries } from "@/lib/api/server/server-queries";

export default async function AdminLayout({ children }: { children: ReactNode }) {
  const currentUser = await serverQueries.getCurrentUser();
  return <DashboardShell mode="admin" currentUser={currentUser}>{children}</DashboardShell>;
}
