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

  const resolution = await mockUnitedPassDataSource.getConsentResolution(resolvedRequestId);

  if (resolution.status !== "valid") {
    return <AuthorizationConsent resolution={resolution} />;
  }

  const currentUser = await mockUnitedPassDataSource.getCurrentUser();
  return <AuthorizationConsent currentUser={currentUser} resolution={resolution} />;
}
