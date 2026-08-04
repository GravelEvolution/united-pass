import type { Metadata } from "next";
import { ForgotPasswordPanel } from "@/features/auth/components/forgot-password-panel";

export const metadata: Metadata = { title: "找回密码" };

export default function ForgotPasswordPage() {
  return <ForgotPasswordPanel />;
}
