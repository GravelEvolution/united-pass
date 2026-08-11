//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Admin page: user detail
//

import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { UserDetail } from "@/features/admin/components/user-detail";
import { serverQueries } from "@/lib/api/server/server-queries";

export const dynamic = "force-dynamic";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ userId: string }>;
}): Promise<Metadata> {
  const { userId } = await params;
  const detail = await serverQueries.getUserDetail(userId);
  return {
    title: detail ? `用户 · ${detail.displayName}` : "用户",
  };
}

export default async function UserDetailPage({
  params,
}: {
  params: Promise<{ userId: string }>;
}) {
  const { userId } = await params;
  const [detail, permissions] = await Promise.all([
    serverQueries.getUserDetail(userId),
    serverQueries.getCurrentPermissions(),
  ]);

  if (!detail) {
    notFound();
  }

  return <UserDetail detail={detail} canManage={permissions.userDisable} />;
}
