//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Admin page: application detail
//

import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { ApplicationDetail } from "@/features/applications/components/application-detail";
import { serverQueries } from "@/lib/api/server/server-queries";

export const dynamic = "force-dynamic";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ applicationId: string }>;
}): Promise<Metadata> {
  const { applicationId } = await params;
  const detail = await serverQueries.getApplicationDetail(applicationId);
  return {
    title: detail ? `OAuth 应用 · ${detail.name}` : "OAuth 应用",
  };
}

export default async function ApplicationDetailPage({
  params,
}: {
  params: Promise<{ applicationId: string }>;
}) {
  const { applicationId } = await params;
  const detail = await serverQueries.getApplicationDetail(applicationId);

  if (!detail) {
    notFound();
  }

  return (
    <Suspense>
      <ApplicationDetail detail={detail} />
    </Suspense>
  );
}
