import type { Metadata } from "next";
import { CredentialPanel } from "@/features/auth/components/credential-panel";

export const metadata: Metadata = { title: "登录" };

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ requestId?: string }>;
}) {
  const { requestId } = await searchParams;

  return <CredentialPanel mode="login" resumeRequestId={requestId} />;
}
