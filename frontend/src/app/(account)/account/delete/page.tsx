//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Account page: account deletion flow
//

import type { Metadata } from "next";
import { PageHeader } from "@/components/common/page-header";
import { AccountDeletionPanel } from "@/features/account/components/privacy-rights";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "注销账户" };

export default async function DeleteAccountPage() {
  const [currentUser, deletion] = await Promise.all([
    serverQueries.getCurrentUser(),
    serverQueries.getAccountDeletion(),
  ]);
  return (
    <>
      <PageHeader
        eyebrow="Account privacy"
        title="注销账户"
        description="永久注销当前账户并删除相关数据。"
      />
      <AccountDeletionPanel userId={currentUser.userId} initialDeletion={deletion} />
    </>
  );
}
