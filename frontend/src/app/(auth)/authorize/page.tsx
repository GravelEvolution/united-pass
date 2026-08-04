import type { Metadata } from "next";
import { AuthorizationConsent } from "@/features/authorization/components/authorization-consent";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "确认应用授权" };

export default async function AuthorizePage() {
  const [currentUser, consentRequest] = await Promise.all([
    mockUnitedPassDataSource.getCurrentUser(),
    mockUnitedPassDataSource.getConsentRequest(),
  ]);

  return <AuthorizationConsent currentUser={currentUser} consentRequest={consentRequest} />;
}
