import { browserFetch } from "@/lib/api/browser/browser-http-client";
import {
  parseAdminStepUpChallenge,
  parseAdminStepUpCompletion,
  parseAdmissionConsensus,
  parseDreamUPApplicationDetail,
  parseOwnReviewResponse,
} from "./response-validators";
import type {
  AdminStepUpAnswer,
  AdminStepUpChallenge,
  AdmissionConsensus,
  DreamUPApplicationDetail,
  OwnReview,
  ReviewRecommendation,
} from "../types";

function applicationPath(eventId: string, applicationId: string): string {
  return `/admin/dreamup/events/${encodeURIComponent(eventId)}/applications/${encodeURIComponent(applicationId)}`;
}

function idempotencyKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function saveOwnReview(
  eventId: string,
  applicationId: string,
  version: number,
  input: { recommendation: ReviewRecommendation; note: string },
): Promise<OwnReview> {
  return parseOwnReviewResponse(await browserFetch<unknown>(`${applicationPath(eventId, applicationId)}/reviews/me`, {
    method: "PUT",
    body: input,
    ifMatchVersion: version,
    idempotencyKey: idempotencyKey(),
  }));
}

async function changeApproval(method: "PUT" | "DELETE", eventId: string, applicationId: string, version: number): Promise<AdmissionConsensus> {
  return parseAdmissionConsensus(await browserFetch<unknown>(`${applicationPath(eventId, applicationId)}/admission-consensus/approval`, {
    method,
    body: {},
    ifMatchVersion: version,
    idempotencyKey: idempotencyKey(),
  }));
}

async function rejectApplication(eventId: string, applicationId: string, version: number, reason: string): Promise<DreamUPApplicationDetail> {
  return parseDreamUPApplicationDetail(await browserFetch<unknown>(`${applicationPath(eventId, applicationId)}/decision`, {
    method: "POST",
    body: { status: "rejected", reason },
    ifMatchVersion: version,
    idempotencyKey: idempotencyKey(),
  }));
}

async function getDashboardStepUpChallenge(eventId: string): Promise<AdminStepUpChallenge> {
  return parseAdminStepUpChallenge(await browserFetch<unknown>(
    `/admin/step-up/challenge?eventId=${encodeURIComponent(eventId)}`,
  ));
}

async function verifyDashboardStepUp(eventId: string, answer: string): Promise<void> {
  parseAdminStepUpCompletion(await browserFetch<unknown>("/admin/step-up/verify", {
    method: "POST",
    idempotencyKey: idempotencyKey(),
    body: {
      eventId,
      answer,
      action: "event.dashboard.read",
      target: eventId,
    },
  }));
}

async function completeDashboardStepUp(
  eventId: string,
  challenge: Exclude<AdminStepUpChallenge, { state: "pending" }>,
  answer: AdminStepUpAnswer,
): Promise<void> {
  if (challenge.state === "must_rotate") {
    if (!("oldAnswer" in answer)) throw new TypeError("Rotation answers are required");
    parseAdminStepUpCompletion(await browserFetch<unknown>("/admin/step-up/rotate", {
      method: "POST",
      ifMatchVersion: challenge.version,
      idempotencyKey: idempotencyKey(),
      body: {
        eventId,
        oldAnswer: answer.oldAnswer,
        question: answer.question,
        answer: answer.answer,
      },
    }));
  }
  await verifyDashboardStepUp(eventId, answer.answer);
}

export const dreamUPAdminCommands = {
  getDashboardStepUpChallenge,
  completeDashboardStepUp,
  saveOwnReview,
  approveAdmission: (eventId: string, applicationId: string, version: number) => changeApproval("PUT", eventId, applicationId, version),
  withdrawAdmissionApproval: (eventId: string, applicationId: string, version: number) => changeApproval("DELETE", eventId, applicationId, version),
  rejectApplication,
};
