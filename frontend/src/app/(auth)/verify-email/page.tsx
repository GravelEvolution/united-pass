//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Email verification page
//

import type { Metadata } from "next";
import { VerifyEmailPanel } from "@/features/auth/components/verify-email-panel";

export const metadata: Metadata = { title: "验证邮箱" };

export default function VerifyEmailPage() {
  return <VerifyEmailPanel />;
}
