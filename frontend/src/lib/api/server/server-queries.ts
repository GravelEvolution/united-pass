import type { UnitedPassQueries } from "@/lib/api/united-pass-data-source";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

/**
 * Server-side query layer.
 *
 * Server Components import queries from this module instead of the mock
 * data source directly. When the real backend API is available, this module
 * will use `server-http-client.ts` to make authenticated HTTP requests
 * that forward the user's session cookie via `next/headers` cookies().
 *
 * See ADR-0004 for the full architecture.
 */
export const serverQueries: UnitedPassQueries = {
  getCurrentUser: () => mockUnitedPassDataSource.getCurrentUser(),
  getAdminCurrentUser: () => mockUnitedPassDataSource.getAdminCurrentUser(),
  getSecurityFactors: () => mockUnitedPassDataSource.getSecurityFactors(),
  getSessions: () => mockUnitedPassDataSource.getSessions(),
  getConsentRequest: () => mockUnitedPassDataSource.getConsentRequest(),
  getConsentResolution: (requestId) => mockUnitedPassDataSource.getConsentResolution(requestId),
  getAuthorizedApplications: () => mockUnitedPassDataSource.getAuthorizedApplications(),
  getAdminDashboard: () => mockUnitedPassDataSource.getAdminDashboard(),
  getUsers: () => mockUnitedPassDataSource.getUsers(),
  getEmployees: () => mockUnitedPassDataSource.getEmployees(),
  getDepartments: () => mockUnitedPassDataSource.getDepartments(),
  getIdentityProviders: () => mockUnitedPassDataSource.getIdentityProviders(),
  getApplications: () => mockUnitedPassDataSource.getApplications(),
  getApplicationDetail: (applicationId) =>
    mockUnitedPassDataSource.getApplicationDetail(applicationId),
  getAvailableScopes: () => mockUnitedPassDataSource.getAvailableScopes(),
  getPolicies: () => mockUnitedPassDataSource.getPolicies(),
  getAuditEvents: () => mockUnitedPassDataSource.getAuditEvents(),
};
