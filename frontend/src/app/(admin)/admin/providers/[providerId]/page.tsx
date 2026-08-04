import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { ProviderDetail as ProviderDetailView } from "@/features/admin/components/provider-detail";
import { serverQueries } from "@/lib/api/server/server-queries";

export const dynamic = "force-dynamic";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ providerId: string }>;
}): Promise<Metadata> {
  const { providerId } = await params;
  const detail = await serverQueries.getProviderDetail(providerId);
  return {
    title: detail ? `Provider · ${detail.displayName}` : "Provider",
  };
}

export default async function ProviderDetailPage({
  params,
}: {
  params: Promise<{ providerId: string }>;
}) {
  const { providerId } = await params;
  const detail = await serverQueries.getProviderDetail(providerId);

  if (!detail) {
    notFound();
  }

  const [syncHistory, conflicts, usersPage] = await Promise.all([
    serverQueries.getDirectorySyncHistory(providerId),
    serverQueries.getSyncConflicts(providerId),
    serverQueries.getUsers({ limit: 100 }),
  ]);

  return (
    <ProviderDetailView
      detail={detail}
      syncHistory={syncHistory}
      conflicts={conflicts}
      users={usersPage.items}
    />
  );
}
