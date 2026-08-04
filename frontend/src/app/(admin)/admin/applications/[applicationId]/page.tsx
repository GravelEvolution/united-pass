import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { ApplicationDetail } from "@/features/applications/components/application-detail";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export async function generateStaticParams() {
  const applications = await mockUnitedPassDataSource.getApplications();
  return applications.map((application) => ({
    applicationId: application.applicationId,
  }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ applicationId: string }>;
}): Promise<Metadata> {
  const { applicationId } = await params;
  const detail = await mockUnitedPassDataSource.getApplicationDetail(applicationId);
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
  const detail = await mockUnitedPassDataSource.getApplicationDetail(applicationId);

  if (!detail) {
    notFound();
  }

  return (
    <Suspense>
      <ApplicationDetail detail={detail} />
    </Suspense>
  );
}
