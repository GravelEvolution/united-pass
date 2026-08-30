import type { Metadata } from "next";
import { dreamUPAdminServerQueries } from "@/features/dreamup-admin/api/server-queries";
import { DreamUPApplicationDirectory } from "@/features/dreamup-admin/components/dreamup-application-directory";
import { DreamUPRouteState } from "@/features/dreamup-admin/components/dreamup-route-state";
import { classifyDreamUPAdminError } from "@/features/dreamup-admin/error-state";
import type { DreamUPApplication, DreamUPEventSummary } from "@/features/dreamup-admin/types";

export const metadata: Metadata = { title: "DreamUP 上海站报名审核" };
export const dynamic = "force-dynamic";

export default async function DreamUPApplicationsPage({ params }: { params: Promise<{ eventId: string }> }) {
  const { eventId } = await params;
  let events: DreamUPEventSummary[] = [];
  let applications: DreamUPApplication[] = [];
  let errorState: ReturnType<typeof classifyDreamUPAdminError> | null = null;
  try {
    [events, applications] = await Promise.all([
      dreamUPAdminServerQueries.getEvents(),
      dreamUPAdminServerQueries.getApplications(eventId),
    ]);
  } catch (error) {
    errorState = classifyDreamUPAdminError(error);
  }
  if (errorState) return <DreamUPRouteState state={errorState} eventId={eventId} />;
  const event = events.find((candidate) => candidate.eventId === eventId);
  if (!event) return <DreamUPRouteState state={{ kind: "not_found", message: "活动不存在，或你无权查看。" }} />;
  return <DreamUPApplicationDirectory eventId={eventId} eventName={event.displayName} applications={applications} />;
}
