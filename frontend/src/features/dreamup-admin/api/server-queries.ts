import { serverFetch } from "@/lib/api/server/server-http-client";
import {
  parseAdmissionConsensus,
  parseDreamUPApplicationDetail,
  parseDreamUPApplications,
  parseDreamUPEvents,
} from "./response-validators";
import type { DreamUPApplicationStatus } from "../types";

function applicationPath(eventId: string, applicationId?: string): string {
  const base = `/admin/dreamup/events/${encodeURIComponent(eventId)}/applications`;
  return applicationId ? `${base}/${encodeURIComponent(applicationId)}` : base;
}

export const dreamUPAdminServerQueries = {
  getEvents: async () => parseDreamUPEvents(await serverFetch<unknown>("/admin/dreamup/events")),
  getApplications: async (eventId: string, filter?: { status?: DreamUPApplicationStatus }) => {
    const query = filter?.status ? `?status=${encodeURIComponent(filter.status)}` : "";
    return parseDreamUPApplications(await serverFetch<unknown>(`${applicationPath(eventId)}${query}`));
  },
  getApplicationDetail: async (eventId: string, applicationId: string) =>
    parseDreamUPApplicationDetail(await serverFetch<unknown>(applicationPath(eventId, applicationId))),
  getAdmissionConsensus: async (eventId: string, applicationId: string) =>
    parseAdmissionConsensus(await serverFetch<unknown>(`${applicationPath(eventId, applicationId)}/admission-consensus`)),
};
