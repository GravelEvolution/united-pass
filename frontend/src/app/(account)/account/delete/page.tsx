import type { Metadata } from "next";
import { PageHeader } from "@/components/common/page-header";
import { UnavailableNotice } from "@/features/account/components/unavailable-notice";

export const metadata: Metadata = { title: "注销账户" };

export default function DeleteAccountPage() {
  return (
    <>
      <PageHeader
        eyebrow="Account privacy"
        title="注销账户"
        description="永久注销当前账户并删除相关数据。"
      />
      <UnavailableNotice
        bannerTitle="账户注销功能尚未开放"
        bannerDescription="该功能正在开发中，暂不支持自助注销账户。相关能力上线后，你将可以在此页面提交注销申请，注销前请确保已了解不可恢复的后果。"
      />
    </>
  );
}
