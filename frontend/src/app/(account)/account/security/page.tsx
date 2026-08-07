//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Account page: security settings overview
//

import type { Metadata } from "next";
import { SecurityOverview } from "@/features/account/components/security-overview";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "登录与安全" };

export default async function SecurityPage() {
  const securityFactors = await serverQueries.getSecurityFactors();
  return <SecurityOverview securityFactors={securityFactors} />;
}
