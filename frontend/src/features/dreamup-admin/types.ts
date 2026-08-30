export type DreamUPAdminRole = "admin" | "senior_admin" | "super_admin";

export type DreamUPEventSummary = {
  eventId: string;
  displayName: string;
  slug?: string;
  role?: DreamUPAdminRole;
  counts?: {
    total: number;
    pending: number;
    accepted: number;
    rejected: number;
  };
};

export type DreamUPApplicationStatus =
  | "submitted"
  | "under_review"
  | "accepted"
  | "waitlisted"
  | "rejected"
  | "withdrawn";

export type DreamUPApplication = {
  id: string;
  eventId: string;
  displayHandle: string;
  status: DreamUPApplicationStatus;
  version: number;
  reviewAnswers: Readonly<Record<string, string | string[]>>;
  submittedAt: string | number | null;
  updatedAt: string | number;
};

export type ReviewRecommendation = "accept" | "waitlist" | "reject" | "needs_discussion";

export type OwnReview = {
  recommendation: ReviewRecommendation;
  note: string;
  version: number;
  updatedAt: string | number;
};

export type DreamUPApplicationDetail = {
  application: DreamUPApplication;
  ownReview: OwnReview | null;
};

export type AdmissionConsensus = {
  roundId: string | null;
  roundNumber: number;
  status: "not_started" | "open" | "finalized" | "cancelled";
  version: number;
  approvalCount: number;
  requiredApprovals: 3;
  ownApproval: boolean;
  applicationStatus: DreamUPApplicationStatus;
};

export type AdminStepUpChallenge =
  | { state: "active" | "must_rotate"; question: string; version: number }
  | { state: "pending" };

export type AdminStepUpAnswer =
  | { answer: string }
  | { oldAnswer: string; question: string; answer: string };
