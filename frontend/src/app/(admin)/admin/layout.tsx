//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Admin console layout shell
//

import type { ReactNode } from "react";
import { redirect } from "next/navigation";
import { DashboardShell } from "@/components/layouts/dashboard-shell";
import { serverQueries } from "@/lib/api/server/server-queries";
import { requireSession } from "@/lib/api/server/server-session";
import { canAccessAdminConsole } from "@/types/permissions";

export const dynamic = "force-dynamic";

export default async function AdminLayout({ children }: { children: ReactNode }) {
  await requireSession();
  const [currentUser, permissions] = await Promise.all([
    serverQueries.getCurrentUser(),
    serverQueries.getCurrentPermissions(),
  ]);
  if (!canAccessAdminConsole(permissions)) {
    redirect("/account");
  }
  return (
    <DashboardShell mode="admin" currentUser={currentUser} permissions={permissions}>
      {children}
    </DashboardShell>
  );
}
