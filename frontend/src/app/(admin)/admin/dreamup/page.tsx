import type { Metadata } from "next";
import { dreamUPAdminServerQueries } from "@/features/dreamup-admin/api/server-queries";
import { DreamUPEventDirectory } from "@/features/dreamup-admin/components/dreamup-event-directory";
import { DreamUPRouteState } from "@/features/dreamup-admin/components/dreamup-route-state";
import { classifyDreamUPAdminError } from "@/features/dreamup-admin/error-state";
import type { DreamUPEventSummary } from "@/features/dreamup-admin/types";

export const metadata: Metadata = { title: "DreamUP 上海站活动管理" };
export const dynamic = "force-dynamic";

export default async function DreamUPAdminPage() {
  let events: DreamUPEventSummary[] = [];
  let errorState: ReturnType<typeof classifyDreamUPAdminError> | null = null;
  try {
    events = await dreamUPAdminServerQueries.getEvents();
  } catch (error) {
    errorState = classifyDreamUPAdminError(error);
  }
  if (errorState) return <DreamUPRouteState state={errorState} />;
  return <DreamUPEventDirectory events={events} />;
}
