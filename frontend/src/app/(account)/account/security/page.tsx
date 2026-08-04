import type { Metadata } from "next";
import { SecurityOverview } from "@/features/account/components/security-overview";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "登录与安全" };

export default async function SecurityPage() {
  const securityFactors = await serverQueries.getSecurityFactors();
  return <SecurityOverview securityFactors={securityFactors} />;
}
