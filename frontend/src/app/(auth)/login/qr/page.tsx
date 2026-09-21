import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { QrLoginPanel } from "@/features/auth/components/qr-login-panel";

export const metadata: Metadata = { title: "扫码登录" };

export default function QrLoginPage() {
  if (process.env.UP_QR_AUTH_ENABLED !== "true") redirect("/login");
  return <QrLoginPanel />;
}
