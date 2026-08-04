import type { Metadata } from "next";
import { ManagementDirectory } from "@/features/admin/components/management-directory";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "Provider 管理" };

export default async function ProvidersPage() {
  const identityProviders = await mockUnitedPassDataSource.getIdentityProviders();
  return <ManagementDirectory kind="providers" records={identityProviders} />;
}
