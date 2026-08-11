//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Admin page: create a new policy
//

import type { Metadata } from "next";
import { PolicyEditor } from "@/features/policies/components/policy-editor";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "新建策略" };
export const dynamic = "force-dynamic";

export default async function NewPolicyPage() {
  const permissions = await serverQueries.getCurrentPermissions();
  return (
    <PolicyEditor
      canManage={permissions.policyManage}
      canPublish={permissions.policyPublish}
    />
  );
}
