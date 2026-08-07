//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Logout page
//

import type { Metadata } from "next";
import { LogoutRedirect } from "@/features/auth/components/logout-redirect";

export const metadata: Metadata = { title: "退出登录" };

export const dynamic = "force-dynamic";

export default function LogoutPage() {
  return <LogoutRedirect />;
}
