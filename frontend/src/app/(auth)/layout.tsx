import type { ReactNode } from "react";
import { AuthShell } from "@/components/layouts/auth-shell";

export default function AuthenticationLayout({ children }: { children: ReactNode }) {
  return <AuthShell>{children}</AuthShell>;
}
