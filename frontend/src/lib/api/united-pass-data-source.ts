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
  OAuthApplication,
  OAuthApplicationDetail,
} from "@/features/applications/types";
import type { ConsentResolution, ConsentRequest } from "@/features/authorization/types";
import type { AuthorizationPolicy } from "@/features/policies/types";
import type { CurrentUser } from "@/types/identity";

export type AdminDashboard = {
  metrics: DashboardMetric[];
  recentEvents: AuditEvent[];
};

export interface UnitedPassDataSource {
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
  createApplication(input: ApplicationCreateInput): Promise<ApplicationCreationResult>;
  getPolicies(): Promise<AuthorizationPolicy[]>;
  getAuditEvents(): Promise<AuditEvent[]>;
}
