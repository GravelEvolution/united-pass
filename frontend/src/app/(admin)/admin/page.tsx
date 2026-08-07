//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Admin console overview page
//

import type { Metadata } from "next";
import { AdminOverview } from "@/features/admin/components/admin-overview";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "管理工作台" };

export default async function AdminPage() {
  const dashboard = await serverQueries.getAdminDashboard();
  return <AdminOverview dashboard={dashboard} />;
}
