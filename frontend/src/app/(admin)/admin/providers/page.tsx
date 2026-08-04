import type { Metadata } from "next";
import { ProvidersTable } from "@/features/admin/components/tables/providers-table";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "Provider 管理" };

export default async function ProvidersPage() {
  const identityProviders = await serverQueries.getIdentityProviders();
  return <ProvidersTable records={identityProviders} />;
}
