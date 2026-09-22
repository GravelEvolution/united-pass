//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Account page: authorized applications management
//

import type { Metadata } from "next";
import { AuthorizedApplicationList } from "@/features/account/components/authorized-application-list";
import { serverQueries } from "@/lib/api/server/server-queries";
import { withActiveSession } from "@/lib/api/server/server-session";

export const metadata: Metadata = { title: "授权应用" };

export default async function AccountApplicationsPage() {
  const applications = await withActiveSession(() => serverQueries.getAuthorizedApplications());
  return <AuthorizedApplicationList applications={applications} />;
}
