import type { Metadata } from "next";
import { PageHeader } from "@/components/common/page-header";
import { UnavailableNotice } from "@/features/account/components/unavailable-notice";

export const metadata: Metadata = { title: "数据导出" };

export default function DataExportPage() {
  return (
    <>
      <PageHeader
        eyebrow="Account privacy"
        title="数据导出"
        description="导出与当前账户关联的个人数据副本。"
      />
      <UnavailableNotice
        bannerTitle="数据导出功能尚未开放"
        bannerDescription="该功能正在开发中，暂不支持导出账户数据。相关能力上线后，你将可以在此页面申请下载与当前账户关联的个人数据副本。"
      />
    </>
  );
}
