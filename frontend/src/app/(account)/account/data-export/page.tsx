//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Account page: personal data export
//

import type { Metadata } from "next";
import { PageHeader } from "@/components/common/page-header";
import { PersonalDataExportPanel } from "@/features/account/components/privacy-rights";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "数据导出" };

export default async function DataExportPage() {
  const currentUser = await serverQueries.getCurrentUser();
  return (
    <>
      <PageHeader
        eyebrow="Account privacy"
        title="数据导出"
        description="导出与当前账户关联的个人数据副本。"
      />
      <PersonalDataExportPanel userId={currentUser.userId} />
    </>
  );
}
