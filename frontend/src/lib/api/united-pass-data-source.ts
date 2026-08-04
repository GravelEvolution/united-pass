import type {
  AuditEvent,
  DashboardMetric,
  DepartmentRecord,
  EmployeeRecord,
  ManagedUser,
} from "@/features/admin/types";
import type { SecurityFactor, UserSession } from "@/features/account/types";
import type { OAuthApplication } from "@/features/applications/types";
import type { ConsentRequest } from "@/features/authorization/types";
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
  getAdminDashboard(): Promise<AdminDashboard>;
  getUsers(): Promise<ManagedUser[]>;
  getEmployees(): Promise<EmployeeRecord[]>;
  getDepartments(): Promise<DepartmentRecord[]>;
  getApplications(): Promise<OAuthApplication[]>;
  getPolicies(): Promise<AuthorizationPolicy[]>;
  getAuditEvents(): Promise<AuditEvent[]>;
}
