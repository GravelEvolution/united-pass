//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Login page
//

import type { Metadata } from "next";
import { CredentialPanel } from "@/features/auth/components/credential-panel";
import { getPublicLoginProviders } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "登录" };

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ requestId?: string; providerError?: string }>;
}) {
  const { requestId, providerError } = await searchParams;
  const loginProviders = await getPublicLoginProviders();

  return (
    <CredentialPanel
      mode="login"
      resumeRequestId={requestId}
      providerError={providerError}
      feishuLoginEnabled={loginProviders.some(
        (provider) => provider.providerId === "provider_feishu" && provider.loginEnabled,
      )}
    />
  );
}
