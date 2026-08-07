//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Forgot password request page
//

import type { Metadata } from "next";
import { ForgotPasswordPanel } from "@/features/auth/components/forgot-password-panel";

export const metadata: Metadata = { title: "找回密码" };

export default function ForgotPasswordPage() {
  return <ForgotPasswordPanel />;
}
