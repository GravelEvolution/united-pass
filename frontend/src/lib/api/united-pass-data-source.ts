import type {
  AuditEvent,
  DashboardMetric,
  DepartmentRecord,
  EmployeeRecord,
  IdentityProviderRecord,
  ManagedUser,
} from "@/features/admin/types";
import type { SecurityFactor, UserSession, AuthorizedApplication } from "@/features/account/types";
import type {
  AllowedScope,
  ApplicationCreateInput,
  ApplicationCreationResult,
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
import type { AuthorizationPolicy } from "@/features/policies/types";
import type { CurrentUser } from "@/types/identity";
import type { CursorPage, PageQuery } from "@/types/pagination";
import type { PermissionCapabilities } from "@/types/permissions";

export type AdminDashboard = {
  metrics: DashboardMetric[];
  recentEvents: AuditEvent[];
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
  getSecurityFactors(): Promise<SecurityFactor[]>;
  getSessions(): Promise<UserSession[]>;
  getConsentResolution(requestId: string): Promise<ConsentResolution>;
  getAuthorizedApplications(): Promise<AuthorizedApplication[]>;
  getAdminDashboard(): Promise<AdminDashboard>;
  getUsers(query?: PageQuery): Promise<CursorPage<ManagedUser>>;
  getEmployees(query?: PageQuery): Promise<CursorPage<EmployeeRecord>>;
  getDepartments(): Promise<DepartmentRecord[]>;
  getIdentityProviders(query?: PageQuery): Promise<CursorPage<IdentityProviderRecord>>;
  getApplications(query?: PageQuery): Promise<CursorPage<OAuthApplication>>;
  getApplicationDetail(applicationId: string): Promise<OAuthApplicationDetail | null>;
  getClientDetail(applicationId: string, clientId: string): Promise<OAuthClient | null>;
  getAvailableScopes(): Promise<AllowedScope[]>;
  getPolicies(query?: PageQuery): Promise<CursorPage<AuthorizationPolicy>>;
  getAuditEvents(query?: PageQuery): Promise<CursorPage<AuditEvent>>;
}

/**
 * Mutations that change server-side state.
 * Both the mock implementation and the future real HTTP-backed implementation
 * must satisfy this contract so pages can swap data sources without UI changes.
 */
export interface UnitedPassCommands {
  createApplication(input: ApplicationCreateInput): Promise<ApplicationCreationResult>;
  createOAuthClient(input: OAuthClientCreateInput): Promise<OAuthClientCreationResult>;
  createApplicationWithInitialClient(input: ApplicationWithInitialClientInput): Promise<ApplicationWithInitialClientResult>;
  decideConsent(requestId: string, decision: ConsentDecision): Promise<{ redirectUrl: string }>;
  revokeGrant(grantId: string): Promise<void>;
  rotateClientSecret(clientId: string): Promise<SecretRotationResult>;
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
  changePassword(currentPassword: string, newPassword: string): Promise<void>;
  enrollTotp(): Promise<{ secret: string; qrCodeUrl: string }>;
  confirmTotpEnrollment(code: string): Promise<void>;
  removeTotp(): Promise<void>;
  startPasskeyEnrollment(): Promise<{ options: string }>;
  completePasskeyEnrollment(attestation: string): Promise<void>;
  removePasskey(credentialId: string): Promise<void>;
  generateRecoveryCodes(): Promise<{ codes: string[] }>;
  revokeOtherSessions(): Promise<void>;
  logout(): Promise<void>;

  // Session management
  revokeSession(sessionId: string): Promise<void>;
}

/**
 * Combined data source contract.
 * Server Components typically receive a full UnitedPassDataSource;
 * Client Components should receive only the Commands they need as callback props
 * to avoid importing server-only modules into the browser bundle.
 */
export type UnitedPassDataSource = UnitedPassQueries & UnitedPassCommands;
