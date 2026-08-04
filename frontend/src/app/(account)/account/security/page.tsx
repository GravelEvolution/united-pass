import type { Metadata } from "next";
import { SecurityOverview } from "@/features/account/components/security-overview";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "登录与安全" };

export default async function SecurityPage() {
  const securityFactors = await mockUnitedPassDataSource.getSecurityFactors();
  return <SecurityOverview securityFactors={securityFactors} />;
}
