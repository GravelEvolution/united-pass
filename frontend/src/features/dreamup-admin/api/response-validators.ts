import { ApiResponseShapeError } from "@/lib/api/response-validators";
import type {
  AdminStepUpChallenge,
  AdmissionConsensus,
  DreamUPAdminRole,
  DreamUPApplication,
  DreamUPApplicationDetail,
  DreamUPApplicationStatus,
  DreamUPEventSummary,
  OwnReview,
  ReviewRecommendation,
} from "../types";

const APPLICATION_FIELDS = new Set([
  "id", "eventId", "displayHandle", "status", "version", "reviewAnswers",
  "submittedAt", "updatedAt",
]);
const REVIEW_BASIC_FIELDS = new Set([
  "city", "affiliation_type", "affiliation_name", "primary_role", "experience_level",
  "skill_tags", "problem_to_solve", "first_build_step", "what_you_bring",
  "collaboration_goal", "portfolio_urls", "team_preference", "existing_team_details",
]);
const SENSITIVE_FIELD = /^(?:legal_?name|email|contact_?email|mobile|phone|photo|portrait|identity|identity_?document|id_?card|legal|legal_?document|answers_?json)$/iu;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: unknown, contract: string): Record<string, unknown> {
  if (!isRecord(value)) throw new ApiResponseShapeError(contract);
  return value;
}

function stringField(value: unknown, contract: string): string {
  if (typeof value !== "string" || value.length === 0) throw new ApiResponseShapeError(contract);
  return value;
}

function integer(value: unknown, contract: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw new ApiResponseShapeError(contract);
  return value as number;
}

function timestamp(value: unknown, contract: string): string | number {
  if ((typeof value !== "string" || value.length === 0) && !Number.isFinite(value)) {
    throw new ApiResponseShapeError(contract);
  }
  return value as string | number;
}

function noUnknownFields(value: Record<string, unknown>, allowed: ReadonlySet<string>, contract: string): void {
  if (Object.keys(value).some((key) => !allowed.has(key) || SENSITIVE_FIELD.test(key))) {
    throw new ApiResponseShapeError(contract);
  }
}

function parseRole(value: unknown): DreamUPAdminRole | undefined {
  if (value === undefined) return undefined;
  if (value !== "admin" && value !== "senior_admin" && value !== "super_admin") {
    throw new ApiResponseShapeError("DreamUPEventSummary.role");
  }
  return value;
}

function parseCounts(value: unknown): DreamUPEventSummary["counts"] {
  if (value === undefined) return undefined;
  const counts = record(value, "DreamUPEventSummary.counts");
  noUnknownFields(counts, new Set(["total", "pending", "accepted", "rejected"]), "DreamUPEventSummary.counts");
  return {
    total: integer(counts.total, "DreamUPEventSummary.counts.total"),
    pending: integer(counts.pending, "DreamUPEventSummary.counts.pending"),
    accepted: integer(counts.accepted, "DreamUPEventSummary.counts.accepted"),
    rejected: integer(counts.rejected, "DreamUPEventSummary.counts.rejected"),
  };
}

function parseEvent(value: unknown): DreamUPEventSummary {
  const event = record(value, "DreamUPEventSummary");
  noUnknownFields(event, new Set(["eventId", "displayName", "slug", "role", "counts"]), "DreamUPEventSummary");
  const slug = event.slug === undefined ? undefined : stringField(event.slug, "DreamUPEventSummary.slug");
  const role = parseRole(event.role);
  const counts = parseCounts(event.counts);
  return {
    eventId: stringField(event.eventId, "DreamUPEventSummary.eventId"),
    displayName: stringField(event.displayName, "DreamUPEventSummary.displayName"),
    ...(slug !== undefined && { slug }),
    ...(role !== undefined && { role }),
    ...(counts !== undefined && { counts }),
  };
}

export function parseDreamUPEvents(value: unknown): DreamUPEventSummary[] {
  const body = record(value, "DreamUPEventsResponse");
  noUnknownFields(body, new Set(["events"]), "DreamUPEventsResponse");
  if (!Array.isArray(body.events)) throw new ApiResponseShapeError("DreamUPEventsResponse.events");
  return body.events.map(parseEvent);
}

function parseStatus(value: unknown, contract: string): DreamUPApplicationStatus {
  if (value !== "submitted" && value !== "under_review" && value !== "accepted" && value !== "waitlisted" && value !== "rejected" && value !== "withdrawn") {
    throw new ApiResponseShapeError(contract);
  }
  return value;
}

function parseReviewAnswers(value: unknown): Readonly<Record<string, string | string[]>> {
  const answers = record(value, "DreamUPApplication.reviewAnswers");
  noUnknownFields(answers, REVIEW_BASIC_FIELDS, "DreamUPApplication.reviewAnswers");
  const parsed: Record<string, string | string[]> = {};
  for (const [key, answer] of Object.entries(answers)) {
    if (typeof answer === "string") parsed[key] = answer;
    else if (Array.isArray(answer) && answer.every((item) => typeof item === "string")) parsed[key] = answer;
    else throw new ApiResponseShapeError(`DreamUPApplication.reviewAnswers.${key}`);
  }
  return parsed;
}

function parseApplication(value: unknown): DreamUPApplication {
  const application = record(value, "DreamUPApplication");
  noUnknownFields(application, APPLICATION_FIELDS, "DreamUPApplication");
  const submittedAt = application.submittedAt === null
    ? null
    : timestamp(application.submittedAt, "DreamUPApplication.submittedAt");
  return {
    id: stringField(application.id, "DreamUPApplication.id"),
    eventId: stringField(application.eventId, "DreamUPApplication.eventId"),
    displayHandle: stringField(application.displayHandle, "DreamUPApplication.displayHandle"),
    status: parseStatus(application.status, "DreamUPApplication.status"),
    version: integer(application.version, "DreamUPApplication.version", 1),
    reviewAnswers: parseReviewAnswers(application.reviewAnswers),
    submittedAt,
    updatedAt: timestamp(application.updatedAt, "DreamUPApplication.updatedAt"),
  };
}

export function parseDreamUPApplications(value: unknown): DreamUPApplication[] {
  const body = record(value, "DreamUPApplicationsResponse");
  noUnknownFields(body, new Set(["applications"]), "DreamUPApplicationsResponse");
  if (!Array.isArray(body.applications)) throw new ApiResponseShapeError("DreamUPApplicationsResponse.applications");
  return body.applications.map(parseApplication);
}

function parseRecommendation(value: unknown): ReviewRecommendation {
  if (value !== "accept" && value !== "waitlist" && value !== "reject" && value !== "needs_discussion") {
    throw new ApiResponseShapeError("OwnReview.recommendation");
  }
  return value;
}

function parseOwnReview(value: unknown): OwnReview | null {
  if (value === null || value === undefined) return null;
  const review = record(value, "OwnReview");
  noUnknownFields(review, new Set(["recommendation", "note", "version", "updatedAt"]), "OwnReview");
  return {
    recommendation: parseRecommendation(review.recommendation),
    note: typeof review.note === "string" ? review.note : (() => { throw new ApiResponseShapeError("OwnReview.note"); })(),
    version: integer(review.version, "OwnReview.version", 1),
    updatedAt: timestamp(review.updatedAt, "OwnReview.updatedAt"),
  };
}

export function parseDreamUPApplicationDetail(value: unknown): DreamUPApplicationDetail {
  const body = record(value, "DreamUPApplicationDetailResponse");
  noUnknownFields(body, new Set(["application", "ownReview"]), "DreamUPApplicationDetailResponse");
  return { application: parseApplication(body.application), ownReview: parseOwnReview(body.ownReview) };
}

export function parseOwnReviewResponse(value: unknown): OwnReview {
  const body = record(value, "OwnReviewResponse");
  noUnknownFields(body, new Set(["review"]), "OwnReviewResponse");
  const review = parseOwnReview(body.review);
  if (!review) throw new ApiResponseShapeError("OwnReviewResponse.review");
  return review;
}

export function parseAdmissionConsensus(value: unknown): AdmissionConsensus {
  const body = record(value, "AdmissionConsensusResponse");
  noUnknownFields(body, new Set(["consensus"]), "AdmissionConsensusResponse");
  const consensus = record(body.consensus, "AdmissionConsensus");
  noUnknownFields(consensus, new Set([
    "roundId", "roundNumber", "status", "version", "approvalCount", "requiredApprovals",
    "ownApproval", "applicationStatus",
  ]), "AdmissionConsensus");
  if (consensus.roundId !== null && typeof consensus.roundId !== "string") throw new ApiResponseShapeError("AdmissionConsensus.roundId");
  if (consensus.status !== "not_started" && consensus.status !== "open" && consensus.status !== "finalized" && consensus.status !== "cancelled") {
    throw new ApiResponseShapeError("AdmissionConsensus.status");
  }
  if (consensus.requiredApprovals !== 3 || typeof consensus.ownApproval !== "boolean") throw new ApiResponseShapeError("AdmissionConsensus");
  return {
    roundId: consensus.roundId,
    roundNumber: integer(consensus.roundNumber, "AdmissionConsensus.roundNumber"),
    status: consensus.status,
    version: integer(consensus.version, "AdmissionConsensus.version"),
    approvalCount: integer(consensus.approvalCount, "AdmissionConsensus.approvalCount"),
    requiredApprovals: 3,
    ownApproval: consensus.ownApproval,
    applicationStatus: parseStatus(consensus.applicationStatus, "AdmissionConsensus.applicationStatus"),
  };
}

export function parseAdminStepUpChallenge(value: unknown): AdminStepUpChallenge {
  const challenge = record(value, "AdminStepUpChallengeResponse");
  noUnknownFields(challenge, new Set([
    "state", "question", "version", "credentialVersion", "lockedUntil",
  ]), "AdminStepUpChallengeResponse");

  if (
    challenge.state === "pending"
    || challenge.state === "pending_enrollment"
    || challenge.state === "recovery_pending"
  ) {
    return { state: "pending" };
  }
  if (challenge.state !== "active" && challenge.state !== "must_rotate") {
    throw new ApiResponseShapeError("AdminStepUpChallengeResponse.state");
  }
  return {
    state: challenge.state,
    question: stringField(challenge.question, "AdminStepUpChallengeResponse.question"),
    version: integer(challenge.version, "AdminStepUpChallengeResponse.version", 1),
  };
}

export function parseAdminStepUpCompletion(value: unknown): void {
  const completion = record(value, "AdminStepUpMutationResponse");
  noUnknownFields(completion, new Set([
    "state", "version", "challengeVersion", "verifiedAt", "expiresAt",
    "reauthenticationToken", "grantId", "replayed",
  ]), "AdminStepUpMutationResponse");
  if (completion.state !== "active") {
    throw new ApiResponseShapeError("AdminStepUpMutationResponse.state");
  }
  integer(completion.challengeVersion, "AdminStepUpMutationResponse.challengeVersion", 1);
}
