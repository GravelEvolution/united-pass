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
  OAuthClientCreateInput,
  OAuthClientCreationResult,
  SecretRotationResult,
} from "@/features/applications/types";
import type { ConsentResolution, ConsentRequest, ConsentDecision } from "@/features/authorization/types";
import type { AuthorizationPolicy } from "@/features/policies/types";
import type { CurrentUser } from "@/types/identity";

export type AdminDashboard = {
  metrics: DashboardMetric[];
  recentEvents: AuditEvent[];
};

/**
 * Read-only data access for Server Components and pages.
 * Implementations may run on the server (reading cookies, forwarding auth)
 * or in the browser (for client-side mutations that call back to the API).
 */
export interface UnitedPassQueries {
  getCurrentUser(): Promise<CurrentUser>;
  getAdminCurrentUser(): Promise<CurrentUser>;
  getSecurityFactors(): Promise<SecurityFactor[]>;
  getSessions(): Promise<UserSession[]>;
  getConsentRequest(): Promise<ConsentRequest>;
  getConsentResolution(requestId: string): Promise<ConsentResolution>;
  getAuthorizedApplications(): Promise<AuthorizedApplication[]>;
  getAdminDashboard(): Promise<AdminDashboard>;
  getUsers(): Promise<ManagedUser[]>;
  getEmployees(): Promise<EmployeeRecord[]>;
  getDepartments(): Promise<DepartmentRecord[]>;
  getIdentityProviders(): Promise<IdentityProviderRecord[]>;
  getApplications(): Promise<OAuthApplication[]>;
  getApplicationDetail(applicationId: string): Promise<OAuthApplicationDetail | null>;
  getAvailableScopes(): Promise<AllowedScope[]>;
  getPolicies(): Promise<AuthorizationPolicy[]>;
  getAuditEvents(): Promise<AuditEvent[]>;
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
}

/**
 * Combined data source contract.
 * Server Components typically receive a full UnitedPassDataSource;
 * Client Components should receive only the Commands they need as callback props
 * to avoid importing server-only modules into the browser bundle.
 */
export type UnitedPassDataSource = UnitedPassQueries & UnitedPassCommands;
