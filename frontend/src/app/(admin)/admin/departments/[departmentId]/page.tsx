import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { DepartmentDetail } from "@/features/admin/components/department-detail";
import { serverQueries } from "@/lib/api/server/server-queries";

export const dynamic = "force-dynamic";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ departmentId: string }>;
}): Promise<Metadata> {
  const { departmentId } = await params;
  const detail = await serverQueries.getDepartmentDetail(departmentId);
  return {
    title: detail ? `部门 · ${detail.name}` : "部门",
  };
}

export default async function DepartmentDetailPage({
  params,
}: {
  params: Promise<{ departmentId: string }>;
}) {
  const { departmentId } = await params;
  const detail = await serverQueries.getDepartmentDetail(departmentId);

  if (!detail) {
    notFound();
  }

  return <DepartmentDetail detail={detail} />;
}
