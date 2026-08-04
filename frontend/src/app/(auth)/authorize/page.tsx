import type { Metadata } from "next";
import { AuthorizationConsent } from "@/features/authorization/components/authorization-consent";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "确认应用授权" };

export default async function AuthorizePage({
  searchParams,
}: {
  searchParams: Promise<{ requestId?: string }>;
}) {
  const { requestId } = await searchParams;
  const resolvedRequestId = requestId ?? "consent_demo_001";

  const [currentUser, resolution] = await Promise.all([
    mockUnitedPassDataSource.getCurrentUser(),
    mockUnitedPassDataSource.getConsentResolution(resolvedRequestId),
  ]);

  return <AuthorizationConsent currentUser={currentUser} resolution={resolution} />;
}
