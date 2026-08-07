//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Admin page: create a new policy
//

import type { Metadata } from "next";
import { PolicyEditor } from "@/features/policies/components/policy-editor";

export const metadata: Metadata = { title: "新建策略" };
export const dynamic = "force-dynamic";

export default function NewPolicyPage() {
  return <PolicyEditor />;
}
