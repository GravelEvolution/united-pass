import type { Metadata } from "next";
import { CredentialPanel } from "@/features/auth/components/credential-panel";

export const metadata: Metadata = { title: "登录" };

export default function LoginPage() {
  return <CredentialPanel mode="login" />;
}
