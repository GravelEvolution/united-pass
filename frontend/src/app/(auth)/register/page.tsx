import type { Metadata } from "next";
import { CredentialPanel } from "@/features/auth/components/credential-panel";

export const metadata: Metadata = { title: "注册" };

export default function RegisterPage() {
  return <CredentialPanel mode="register" />;
}
