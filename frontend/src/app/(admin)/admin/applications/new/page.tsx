//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Admin page: create a new application
//

import type { Metadata } from "next";
import { ApplicationCreateForm } from "@/features/applications/components/application-create-form";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "注册 OAuth 应用" };

export default async function NewApplicationPage() {
  const availableScopes = await serverQueries.getAvailableScopes();
  return <ApplicationCreateForm availableScopes={availableScopes} />;
}
