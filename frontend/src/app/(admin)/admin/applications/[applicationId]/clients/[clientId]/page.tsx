import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { ClientDetail } from "@/features/applications/components/client-detail";
import { serverQueries } from "@/lib/api/server/server-queries";

export async function generateStaticParams() {
  const applications = await serverQueries.getApplications();
  const params: { applicationId: string; clientId: string }[] = [];
  for (const app of applications) {
    const detail = await serverQueries.getApplicationDetail(app.applicationId);
    if (detail) {
      for (const client of detail.clients) {
        params.push({ applicationId: app.applicationId, clientId: client.clientId });
      }
    }
  }
  return params;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ applicationId: string; clientId: string }>;
}): Promise<Metadata> {
  const { applicationId, clientId } = await params;
  const [appDetail, client] = await Promise.all([
    serverQueries.getApplicationDetail(applicationId),
    serverQueries.getClientDetail(applicationId, clientId),
  ]);
  return {
    title: client ? `${client.name} · ${appDetail?.name ?? "OAuth 应用"}` : "OAuth 客户端",
  };
}

export default async function ClientDetailPage({
  params,
}: {
  params: Promise<{ applicationId: string; clientId: string }>;
}) {
  const { applicationId, clientId } = await params;
  const [appDetail, client] = await Promise.all([
    serverQueries.getApplicationDetail(applicationId),
    serverQueries.getClientDetail(applicationId, clientId),
  ]);

  if (!appDetail || !client) {
    notFound();
  }

  return (
    <Suspense>
      <ClientDetail
        applicationId={applicationId}
        applicationName={appDetail.name}
        applicationStatus={appDetail.status}
        client={client}
      />
    </Suspense>
  );
}
