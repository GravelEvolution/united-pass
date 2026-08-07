//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: OAuth authorization and consent page
//

import type { Metadata } from "next";
import { AuthorizationConsent } from "@/features/authorization/components/authorization-consent";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "确认应用授权" };

export default async function AuthorizePage({
  searchParams,
}: {
  searchParams: Promise<{ requestId?: string }>;
}) {
  const { requestId } = await searchParams;
  const resolvedRequestId = requestId ?? "consent_demo_001";

  const resolution = await serverQueries.getConsentResolution(resolvedRequestId);

  if (resolution.status !== "valid") {
    return <AuthorizationConsent resolution={resolution} />;
  }

  const currentUser = await serverQueries.getCurrentUser();
  return <AuthorizationConsent currentUser={currentUser} resolution={resolution} />;
}
