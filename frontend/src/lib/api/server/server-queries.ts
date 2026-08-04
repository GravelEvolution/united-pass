import type { UnitedPassQueries } from "@/lib/api/united-pass-data-source";
import type { PageQuery } from "@/types/pagination";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

/**
 * Server-side query layer.
 *
 * Server Components import queries from this module instead of the mock
 * data source directly. When the real backend API is available, this module
 * will use `server-http-client.ts` to make authenticated HTTP requests
 * that forward the user's session cookie via `next/headers` cookies().
 *
 * List endpoints accept PageQuery and return CursorPage<T> so the backend
 * can return partial results without the frontend loading all records.
 *
 * See ADR-0004 for the full architecture.
 * See ADR-0006 for the deployment topology.
 */
export const serverQueries: UnitedPassQueries = {
  getCurrentUser: () => mockUnitedPassDataSource.getCurrentUser(),
  getCurrentPermissions: () => mockUnitedPassDataSource.getCurrentPermissions(),
  getSecurityFactors: () => mockUnitedPassDataSource.getSecurityFactors(),
  getSessions: () => mockUnitedPassDataSource.getSessions(),
  getConsentResolution: (requestId) => mockUnitedPassDataSource.getConsentResolution(requestId),
  getAuthorizedApplications: () => mockUnitedPassDataSource.getAuthorizedApplications(),
  getAdminDashboard: () => mockUnitedPassDataSource.getAdminDashboard(),
  getUsers: (query?: PageQuery) => mockUnitedPassDataSource.getUsers(query),
  getEmployees: (query?: PageQuery) => mockUnitedPassDataSource.getEmployees(query),
  getDepartments: () => mockUnitedPassDataSource.getDepartments(),
  getIdentityProviders: (query?: PageQuery) => mockUnitedPassDataSource.getIdentityProviders(query),
  getApplications: (query?: PageQuery) => mockUnitedPassDataSource.getApplications(query),
  getApplicationDetail: (applicationId) =>
    mockUnitedPassDataSource.getApplicationDetail(applicationId),
  getClientDetail: (applicationId, clientId) =>
    mockUnitedPassDataSource.getClientDetail(applicationId, clientId),
  getAvailableScopes: () => mockUnitedPassDataSource.getAvailableScopes(),
  getPolicies: (query?: PageQuery) => mockUnitedPassDataSource.getPolicies(query),
  getAuditEvents: (query?: PageQuery) => mockUnitedPassDataSource.getAuditEvents(query),
};
