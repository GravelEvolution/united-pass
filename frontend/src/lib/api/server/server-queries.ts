//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Server-side read-only API queries
//

import type { UnitedPassQueries } from "@/lib/api/united-pass-data-source";
import type { AuditQuery } from "@/features/admin/types";
import type { PageQuery } from "@/types/pagination";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";
import { USE_MOCK_DATA_SOURCE } from "@/lib/api/data-source-mode";
import { serverFetch } from "@/lib/api/server/server-http-client";
import {
  parseAuthorizedApplications,
  parseConsentResolution,
  parseCurrentUser,
  parseSecuritySummary,
  parseUserSessions,
} from "@/lib/api/response-validators";

/**
 * Server-side query layer.
 *
 * Server Components import queries from this module instead of the mock
 * data source directly. Seams migrate from the mock source to real HTTP
 * one at a time (frontend-freeze-v1.md §5): migrated seams call
 * `server-http-client.ts` with session cookie forwarding and narrow the
 * untrusted response onto the frozen contract types; unmigrated seams keep
 * the mock source until their backend contract lands.
 *
 * Migrated seams: getCurrentUser, getSecuritySummary, getSessions,
 * getConsentResolution, getAuthorizedApplications.
 *
 * List endpoints accept PageQuery and return CursorPage<T> so the backend
 * can return partial results without the frontend loading all records.
 *
 * See ADR-0004 for the full architecture.
 * See ADR-0006 for the deployment topology.
 */
export const serverQueries: UnitedPassQueries = {
  getCurrentUser: USE_MOCK_DATA_SOURCE
    ? () => mockUnitedPassDataSource.getCurrentUser()
    : async () => parseCurrentUser(await serverFetch<unknown>("/me")),
  getCurrentPermissions: () => mockUnitedPassDataSource.getCurrentPermissions(),
  getSecuritySummary: USE_MOCK_DATA_SOURCE
    ? () => mockUnitedPassDataSource.getSecuritySummary()
    : async () => parseSecuritySummary(await serverFetch<unknown>("/me/security")),
  getSessions: USE_MOCK_DATA_SOURCE
    ? () => mockUnitedPassDataSource.getSessions()
    : async () => parseUserSessions(await serverFetch<unknown>("/me/sessions")),
  getConsentResolution: USE_MOCK_DATA_SOURCE
    ? (requestId) => mockUnitedPassDataSource.getConsentResolution(requestId)
    : async (requestId) =>
        parseConsentResolution(
          await serverFetch<unknown>(
            `/authorization/requests/${encodeURIComponent(requestId)}`,
          ),
        ),
  getAuthorizedApplications: USE_MOCK_DATA_SOURCE
    ? () => mockUnitedPassDataSource.getAuthorizedApplications()
    : async () =>
        parseAuthorizedApplications(
          await serverFetch<unknown>("/me/authorized-applications"),
        ),
  getAdminDashboard: () => mockUnitedPassDataSource.getAdminDashboard(),
  getUsers: (query?: PageQuery) => mockUnitedPassDataSource.getUsers(query),
  getUserDetail: (userId) => mockUnitedPassDataSource.getUserDetail(userId),
  getEmployees: (query?: PageQuery) => mockUnitedPassDataSource.getEmployees(query),
  getEmployeeDetail: (userId) => mockUnitedPassDataSource.getEmployeeDetail(userId),
  getDepartments: () => mockUnitedPassDataSource.getDepartments(),
  getDepartmentDetail: (departmentId) => mockUnitedPassDataSource.getDepartmentDetail(departmentId),
  getIdentityProviders: (query?: PageQuery) => mockUnitedPassDataSource.getIdentityProviders(query),
  getProviderDetail: (providerId) => mockUnitedPassDataSource.getProviderDetail(providerId),
  getDirectorySyncHistory: (providerId) => mockUnitedPassDataSource.getDirectorySyncHistory(providerId),
  getSyncConflicts: (providerId) => mockUnitedPassDataSource.getSyncConflicts(providerId),
  getApplications: (query?: PageQuery) => mockUnitedPassDataSource.getApplications(query),
  getApplicationDetail: (applicationId) =>
    mockUnitedPassDataSource.getApplicationDetail(applicationId),
  getClientDetail: (applicationId, clientId) =>
    mockUnitedPassDataSource.getClientDetail(applicationId, clientId),
  getAvailableScopes: () => mockUnitedPassDataSource.getAvailableScopes(),
  getPolicies: (query?: PageQuery) => mockUnitedPassDataSource.getPolicies(query),
  getPolicyDetail: (policyId) => mockUnitedPassDataSource.getPolicyDetail(policyId),
  getAuditEvents: (query?: AuditQuery) => mockUnitedPassDataSource.getAuditEvents(query),
};
