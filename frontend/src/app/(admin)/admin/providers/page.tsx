import type { Metadata } from "next";
import { ProvidersTable } from "@/features/admin/components/tables/providers-table";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "Provider 管理" };

export default async function ProvidersPage() {
  const identityProviders = await mockUnitedPassDataSource.getIdentityProviders();
  return <ProvidersTable records={identityProviders} />;
}
