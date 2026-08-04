import type { Metadata } from "next";
import { LogoutRedirect } from "@/features/auth/components/logout-redirect";

export const metadata: Metadata = { title: "退出登录" };

export const dynamic = "force-dynamic";

export default function LogoutPage() {
  return <LogoutRedirect />;
}
