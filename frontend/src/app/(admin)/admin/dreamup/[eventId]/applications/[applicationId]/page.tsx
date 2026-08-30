import type { Metadata } from "next";
import { dreamUPAdminServerQueries } from "@/features/dreamup-admin/api/server-queries";
import { DreamUPApplicationReview } from "@/features/dreamup-admin/components/dreamup-application-review";
import { DreamUPRouteState } from "@/features/dreamup-admin/components/dreamup-route-state";
import { classifyDreamUPAdminError } from "@/features/dreamup-admin/error-state";
import type { AdmissionConsensus, DreamUPApplicationDetail } from "@/features/dreamup-admin/types";

export const metadata: Metadata = { title: "DreamUP 在线审核" };
export const dynamic = "force-dynamic";

export default async function DreamUPApplicationPage({ params }: { params: Promise<{ eventId: string; applicationId: string }> }) {
  const { eventId, applicationId } = await params;
  let detail: DreamUPApplicationDetail | null = null;
  let consensus: AdmissionConsensus | null = null;
  let errorState: ReturnType<typeof classifyDreamUPAdminError> | null = null;
  try {
    [detail, consensus] = await Promise.all([
      dreamUPAdminServerQueries.getApplicationDetail(eventId, applicationId),
      dreamUPAdminServerQueries.getAdmissionConsensus(eventId, applicationId),
    ]);
  } catch (error) {
    errorState = classifyDreamUPAdminError(error);
  }
  if (errorState || !detail || !consensus) {
    return <DreamUPRouteState state={errorState ?? { kind: "unavailable", message: "DreamUP 管理服务暂时不可用，请稍后重试。" }} eventId={eventId} />;
  }
  return <DreamUPApplicationReview eventId={eventId} initialDetail={detail} initialConsensus={consensus} />;
}
