//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Authentication section layout shell
//

import type { ReactNode } from "react";
import { AuthShell } from "@/components/layouts/auth-shell";

export default function AuthenticationLayout({ children }: { children: ReactNode }) {
  return <AuthShell>{children}</AuthShell>;
}
