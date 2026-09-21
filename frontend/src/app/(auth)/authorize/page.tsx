//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: OAuth authorization and consent page
//

import type { Metadata } from "next";
import {
  AuthorizationConsent,
  MissingRequestIdCard,
} from "@/features/authorization/components/authorization-consent";
import { USE_MOCK_DATA_SOURCE } from "@/lib/api/data-source-mode";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "确认应用授权" };

type Settled<T> =
  | { status: "fulfilled"; value: T }
  | { status: "rejected"; reason: unknown };

function settle<T>(promise: Promise<T>): Promise<Settled<T>> {
  return promise.then(
    (value) => ({ status: "fulfilled", value }),
    (reason: unknown) => ({ status: "rejected", reason }),
  );
}

export default async function AuthorizePage({
  searchParams,
}: {
  searchParams: Promise<{ requestId?: string }>;
}) {
  const { requestId } = await searchParams;

  // Real mode resolves only caller-supplied opaque request IDs; the
  // consent_demo_001 fallback exists exclusively for the frozen mock source.
  if (!requestId && !USE_MOCK_DATA_SOURCE) {
    return <MissingRequestIdCard />;
  }

  // The two reads are independent once the login response has established the
  // session cookie. Attach the rejection handler before awaiting consent so a
  // terminal authorization result remains authoritative even if /me rejects.
  const currentUserResult = settle(serverQueries.getCurrentUser());
  const resolution = await serverQueries.getConsentResolution(
    requestId ?? "consent_demo_001",
  );

  if (resolution.status !== "valid") {
    return <AuthorizationConsent resolution={resolution} />;
  }

  const settledCurrentUser = await currentUserResult;
  if (settledCurrentUser.status === "rejected") {
    throw settledCurrentUser.reason;
  }

  return (
    <AuthorizationConsent
      currentUser={settledCurrentUser.value}
      resolution={resolution}
    />
  );
}
