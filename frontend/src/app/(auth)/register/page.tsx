//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Registration page
//

import type { Metadata } from "next";
import { CredentialPanel } from "@/features/auth/components/credential-panel";

export const metadata: Metadata = { title: "注册" };

export default function RegisterPage() {
  return <CredentialPanel mode="register" />;
}
