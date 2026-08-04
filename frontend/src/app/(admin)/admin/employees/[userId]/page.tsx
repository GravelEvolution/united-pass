import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { EmployeeDetail } from "@/features/admin/components/employee-detail";
import { serverQueries } from "@/lib/api/server/server-queries";

export const dynamic = "force-dynamic";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ userId: string }>;
}): Promise<Metadata> {
  const { userId } = await params;
  const detail = await serverQueries.getEmployeeDetail(userId);
  return {
    title: detail ? `员工 · ${detail.displayName}` : "员工",
  };
}

export default async function EmployeeDetailPage({
  params,
}: {
  params: Promise<{ userId: string }>;
}) {
  const { userId } = await params;
  const detail = await serverQueries.getEmployeeDetail(userId);

  if (!detail) {
    notFound();
  }

  return <EmployeeDetail detail={detail} />;
}
