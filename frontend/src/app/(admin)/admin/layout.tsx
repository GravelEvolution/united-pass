import type { ReactNode } from "react";
import { DashboardShell } from "@/components/layouts/dashboard-shell";
import { serverQueries } from "@/lib/api/server/server-queries";

export const dynamic = "force-dynamic";

export default async function AdminLayout({ children }: { children: ReactNode }) {
  const [currentUser, permissions] = await Promise.all([
    serverQueries.getCurrentUser(),
    serverQueries.getCurrentPermissions(),
  ]);
  return (
    <DashboardShell mode="admin" currentUser={currentUser} permissions={permissions}>
      {children}
    </DashboardShell>
  );
}
