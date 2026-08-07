//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Admin console layout shell
//

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
