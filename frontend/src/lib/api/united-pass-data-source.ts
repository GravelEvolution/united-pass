//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Data source abstraction for the United Pass API
//

import type {
  AuditEvent,
  AuditExportResult,
  AuditQuery,
  DashboardMetric,
  DepartmentDetail,
  DepartmentRecord,
  DirectorySyncHistoryEntry,
  DirectorySyncResult,
  EmployeeDetail,
  EmployeeLinkInput,
  EmployeeRecord,
  IdentityProviderRecord,
  ManagedUser,
  ProviderDetail,
  SyncConflict,
  UserDetail,
} from "@/features/admin/types";
import type {
  AuthorizedApplication,
  PasskeyEnrollment,
  PasskeyEnrollmentConfirmation,
  ReauthenticationGrant,
  ReauthenticationInput,
  ReauthenticationOutcome,
  SecuritySummary,
  SerializedAssertionCredential,
  SerializedAttestationCredential,
  TotpEnrollment,
  UserSession,
} from "@/features/account/types";
import type {
  AllowedScope,
  ApplicationStatus,
  ApplicationUpdateInput,
  ApplicationWithInitialClientInput,
  ApplicationWithInitialClientResult,
  OAuthApplication,
  OAuthApplicationDetail,
  OAuthClient,
  OAuthClientCreateInput,
  OAuthClientCreationResult,
  SecretRotationResult,
} from "@/features/applications/types";
import type { ConsentResolution, ConsentDecision } from "@/features/authorization/types";
import type {
  AuthorizationPolicy,
  PolicyDetail,
  PolicyDraftInput,
  PolicySimulationInput,
  PolicySimulationResult,
} from "@/features/policies/types";
import type { CurrentUser } from "@/types/identity";
import type { CursorPage, PageQuery } from "@/types/pagination";
import type { PermissionCapabilities } from "@/types/permissions";

export type AdminDashboard = {
  metrics: DashboardMetric[];
  recentEvents: AuditEvent[];
};

export type BrowserCommandOptions = {
  signal?: AbortSignal;
};

/**
 * Read-only data access for Server Components and pages.
 * Implementations may run on the server (reading cookies, forwarding auth)
 * or in the browser (for client-side mutations that call back to the API).
 *
 * List endpoints use cursor pagination (CursorPage<T>) so the backend can
 * return partial results without the frontend loading all records.
 */
export interface UnitedPassQueries {
  getCurrentUser(): Promise<CurrentUser>;
  getCurrentPermissions(): Promise<PermissionCapabilities>;
  getSecuritySummary(): Promise<SecuritySummary>;
  getSessions(): Promise<UserSession[]>;
  getConsentResolution(requestId: string): Promise<ConsentResolution>;
  getAuthorizedApplications(): Promise<AuthorizedApplication[]>;
  getAdminDashboard(): Promise<AdminDashboard>;
  getUsers(query?: PageQuery): Promise<CursorPage<ManagedUser>>;
  getUserDetail(userId: string): Promise<UserDetail | null>;
  getEmployees(query?: PageQuery): Promise<CursorPage<EmployeeRecord>>;
  getEmployeeDetail(userId: string): Promise<EmployeeDetail | null>;
  getDepartments(): Promise<DepartmentRecord[]>;
  getDepartmentDetail(departmentId: string): Promise<DepartmentDetail | null>;
  getIdentityProviders(query?: PageQuery): Promise<CursorPage<IdentityProviderRecord>>;
  getProviderDetail(providerId: string): Promise<ProviderDetail | null>;
  getDirectorySyncHistory(providerId?: string): Promise<DirectorySyncHistoryEntry[]>;
  getSyncConflicts(providerId?: string): Promise<SyncConflict[]>;
  getApplications(query?: PageQuery): Promise<CursorPage<OAuthApplication>>;
  getApplicationDetail(applicationId: string): Promise<OAuthApplicationDetail | null>;
  getClientDetail(applicationId: string, clientId: string): Promise<OAuthClient | null>;
  getAvailableScopes(): Promise<AllowedScope[]>;
  getPolicies(query?: PageQuery): Promise<CursorPage<AuthorizationPolicy>>;
  getPolicyDetail(policyId: string): Promise<PolicyDetail | null>;
  getAuditEvents(query?: AuditQuery): Promise<CursorPage<AuditEvent>>;
}

/**
 * Mutations that change server-side state.
 * Both the mock implementation and the future real HTTP-backed implementation
 * must satisfy this contract so pages can swap data sources without UI changes.
 *
 * Mirrors the backend REST contract: standalone application creation is not
 * exposed (applications are always created with an initial client via
 * `with-initial-client`), and secret rotation is scoped to its parent
 * application in the URL.
 */
export interface UnitedPassCommands {
  createOAuthClient(input: OAuthClientCreateInput): Promise<OAuthClientCreationResult>;
  createApplicationWithInitialClient(input: ApplicationWithInitialClientInput): Promise<ApplicationWithInitialClientResult>;
  decideConsent(requestId: string, decision: ConsentDecision): Promise<{ redirectUrl: string }>;
  revokeGrant(grantId: string): Promise<void>;
  rotateClientSecret(applicationId: string, clientId: string): Promise<SecretRotationResult>;
  updateApplicationStatus(applicationId: string, status: ApplicationStatus): Promise<void>;
  deleteApplication(applicationId: string): Promise<void>;
  updateApplication(applicationId: string, input: ApplicationUpdateInput): Promise<void>;

  // Account profile
  updateProfile(input: { displayName?: string; nickname?: string }): Promise<void>;
  uploadAvatar(file: File): Promise<{ avatarUrl: string }>;
  requestEmailChange(email: string): Promise<{ requestId: string }>;
  verifyEmailChange(requestId: string, code: string): Promise<void>;
  requestPhoneChange(phone: string): Promise<{ requestId: string }>;
  verifyPhoneChange(requestId: string, code: string): Promise<void>;

  // Security
  changePassword(newPassword: string, reauthToken: string, options?: BrowserCommandOptions): Promise<void>;
  beginTotpEnrollment(reauthToken: string, options?: BrowserCommandOptions): Promise<TotpEnrollment>;
  confirmTotpEnrollment(input: { enrollmentToken: string; code: string }): Promise<void>;
  cancelTotpEnrollment(enrollmentToken: string): Promise<void>;
  removeTotp(reauthToken: string, options?: BrowserCommandOptions): Promise<SecuritySummary>;
  requestReauthentication(input: ReauthenticationInput, options?: BrowserCommandOptions): Promise<ReauthenticationOutcome>;
  completeReauthenticationMfa(input: {
    reauthToken: string;
    method: "totp" | "passkey";
    code?: string;
    passkeyAssertion?: SerializedAssertionCredential;
  }, options?: BrowserCommandOptions): Promise<ReauthenticationGrant>;
  startPasskeyEnrollment(
    reauthToken: string,
    options?: BrowserCommandOptions,
  ): Promise<PasskeyEnrollment>;
  completePasskeyEnrollment(input: {
    enrollmentToken: string;
    passkeyId: string;
    publicKeyCredential: SerializedAttestationCredential;
    passkeyName: string;
  }, options?: BrowserCommandOptions): Promise<PasskeyEnrollmentConfirmation>;
  cancelPasskeyEnrollment(enrollmentToken: string): Promise<void>;
  removePasskey(passkeyId: string, reauthToken: string, options?: BrowserCommandOptions): Promise<SecuritySummary>;
  generateRecoveryCodes(): Promise<{ codes: string[] }>;
  revokeOtherSessions(): Promise<{ revoked: number }>;
  logout(): Promise<void>;

  // Session management
  revokeOwnSession(sessionId: string): Promise<void>;

  // Admin user management
  updateUserStatus(userId: string, status: "active" | "disabled"): Promise<void>;
  revokeUserSession(userId: string, sessionId: string): Promise<void>;
  revokeUserSessions(userId: string): Promise<void>;
  linkEmployeeProfile(input: EmployeeLinkInput): Promise<void>;
  offboardEmployee(userId: string): Promise<void>;

  // Policy management
  savePolicyDraft(input: PolicyDraftInput): Promise<{ policyId: string; version: number }>;
  publishPolicy(policyId: string): Promise<{ version: number }>;
  simulatePolicy(input: PolicySimulationInput): Promise<PolicySimulationResult>;

  // Provider management
  syncProviderDirectory(providerId: string): Promise<DirectorySyncResult>;
  resolveSyncConflict(conflictId: string, userId: string): Promise<void>;
  ignoreSyncConflict(conflictId: string): Promise<void>;

  // Audit export
  exportAuditEvents(query: AuditQuery): Promise<AuditExportResult>;
}

/**
 * Combined data source contract.
 * Server Components typically receive a full UnitedPassDataSource;
 * Client Components should receive only the Commands they need as callback props
 * to avoid importing server-only modules into the browser bundle.
 */
export type UnitedPassDataSource = UnitedPassQueries & UnitedPassCommands;
