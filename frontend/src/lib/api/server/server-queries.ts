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
import { isApiError } from "@/lib/api/api-error";
import {
  parseAccountDeletion,
  parseAuthorizedApplications,
  parseAuditEvents,
  parseConsentResolution,
  parseCurrentUser,
  parseDepartmentDetail,
  parseDepartments,
  parseEmployeeDetail,
  parseEmployees,
  parseDirectorySyncHistory,
  parseIdentityProviders,
  parseManagedUsers,
  parsePermissionCapabilities,
  parsePolicies,
  parsePolicyDetail,
  parseSecuritySummary,
  parseProviderDetail,
  parsePublicLoginProviders,
  parseSyncConflicts,
  parseUserDetail,
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
 * Migrated seams: account/session/consent reads plus the complete Phase 5
 * identity and workforce plane.
 *
 * List endpoints accept PageQuery and return CursorPage<T> so the backend
 * can return partial results without the frontend loading all records.
 *
 * See ADR-0004 for the full architecture.
 * See ADR-0006 for the deployment topology.
 */
function withPageQuery(path: string, query?: PageQuery): string {
  if (!query) return path;
  const parameters = new URLSearchParams();
  if (query.cursor) parameters.set("cursor", query.cursor);
  if (query.limit !== undefined) parameters.set("limit", String(query.limit));
  if (query.query) parameters.set("query", query.query);
  if (query.sort) parameters.set("sort", query.sort);
  if (query.status) parameters.set("status", query.status);
  const encoded = parameters.toString();
  return encoded ? `${path}?${encoded}` : path;
}

function withAuditQuery(path: string, query?: AuditQuery): string {
  if (!query) return path;
  const parameters = new URLSearchParams();
  if (query.cursor) parameters.set("cursor", query.cursor);
  if (query.limit !== undefined) parameters.set("limit", String(query.limit));
  if (query.query) parameters.set("query", query.query);
  if (query.eventType) parameters.set("eventType", query.eventType);
  if (query.result) parameters.set("result", query.result);
  if (query.actorName) parameters.set("actorName", query.actorName);
  if (query.requestId) parameters.set("requestId", query.requestId);
  if (query.from) parameters.set("from", query.from);
  if (query.to) parameters.set("to", query.to);
  const encoded = parameters.toString();
  return encoded ? `${path}?${encoded}` : path;
}

async function nullableServerQuery<T>(
  path: string,
  parser: (value: unknown) => T,
): Promise<T | null> {
  try {
    return parser(await serverFetch<unknown>(path));
  } catch (error) {
    if (isApiError(error) && error.kind === "not_found") return null;
    throw error;
  }
}

export const serverQueries: UnitedPassQueries = {
  getCurrentUser: USE_MOCK_DATA_SOURCE
    ? () => mockUnitedPassDataSource.getCurrentUser()
    : async () => parseCurrentUser(await serverFetch<unknown>("/me")),
  getCurrentPermissions: USE_MOCK_DATA_SOURCE
    ? () => mockUnitedPassDataSource.getCurrentPermissions()
    : async () => parsePermissionCapabilities(await serverFetch<unknown>("/me/permissions")),
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
  getAccountDeletion: USE_MOCK_DATA_SOURCE
    ? () => mockUnitedPassDataSource.getAccountDeletion()
    : async () => parseAccountDeletion(
        await serverFetch<unknown>("/me/account-deletion"),
      ),
  getAdminDashboard: () => mockUnitedPassDataSource.getAdminDashboard(),
  getUsers: USE_MOCK_DATA_SOURCE
    ? (query?: PageQuery) => mockUnitedPassDataSource.getUsers(query)
    : async (query?: PageQuery) => parseManagedUsers(
        await serverFetch<unknown>(withPageQuery("/admin/users", query)),
      ),
  getUserDetail: USE_MOCK_DATA_SOURCE
    ? (userId) => mockUnitedPassDataSource.getUserDetail(userId)
    : (userId) => nullableServerQuery(
        `/admin/users/${encodeURIComponent(userId)}`,
        parseUserDetail,
      ),
  getEmployees: USE_MOCK_DATA_SOURCE
    ? (query?: PageQuery) => mockUnitedPassDataSource.getEmployees(query)
    : async (query?: PageQuery) => parseEmployees(
        await serverFetch<unknown>(withPageQuery("/admin/employees", query)),
      ),
  getEmployeeDetail: USE_MOCK_DATA_SOURCE
    ? (userId) => mockUnitedPassDataSource.getEmployeeDetail(userId)
    : (userId) => nullableServerQuery(
        `/admin/users/${encodeURIComponent(userId)}/employee-profile`,
        parseEmployeeDetail,
      ),
  getDepartments: USE_MOCK_DATA_SOURCE
    ? (query?: PageQuery) => mockUnitedPassDataSource.getDepartments(query)
    : async (query?: PageQuery) => parseDepartments(
        await serverFetch<unknown>(withPageQuery("/admin/departments", query)),
      ),
  getDepartmentDetail: USE_MOCK_DATA_SOURCE
    ? (departmentId) => mockUnitedPassDataSource.getDepartmentDetail(departmentId)
    : (departmentId) => nullableServerQuery(
        `/admin/departments/${encodeURIComponent(departmentId)}`,
        parseDepartmentDetail,
      ),
  getIdentityProviders: USE_MOCK_DATA_SOURCE
    ? (query?: PageQuery) => mockUnitedPassDataSource.getIdentityProviders(query)
    : async (query?: PageQuery) => parseIdentityProviders(
        await serverFetch<unknown>(withPageQuery("/admin/identity-providers", query)),
      ),
  getProviderDetail: USE_MOCK_DATA_SOURCE
    ? (providerId) => mockUnitedPassDataSource.getProviderDetail(providerId)
    : (providerId) => nullableServerQuery(
        `/admin/identity-providers/${encodeURIComponent(providerId)}`,
        parseProviderDetail,
      ),
  getDirectorySyncHistory: USE_MOCK_DATA_SOURCE
    ? (providerId) => mockUnitedPassDataSource.getDirectorySyncHistory(providerId)
    : async (providerId) => parseDirectorySyncHistory(
        await serverFetch<unknown>(
          `/admin/identity-providers/${encodeURIComponent(providerId)}/directory-syncs`,
        ),
      ),
  getSyncConflicts: USE_MOCK_DATA_SOURCE
    ? (providerId) => mockUnitedPassDataSource.getSyncConflicts(providerId)
    : async (providerId) => parseSyncConflicts(
        await serverFetch<unknown>(
          `/admin/identity-providers/${encodeURIComponent(providerId)}/sync-conflicts`,
        ),
      ),
  getApplications: (query?: PageQuery) => mockUnitedPassDataSource.getApplications(query),
  getApplicationDetail: (applicationId) =>
    mockUnitedPassDataSource.getApplicationDetail(applicationId),
  getClientDetail: (applicationId, clientId) =>
    mockUnitedPassDataSource.getClientDetail(applicationId, clientId),
  getAvailableScopes: () => mockUnitedPassDataSource.getAvailableScopes(),
  getPolicies: USE_MOCK_DATA_SOURCE
    ? (query?: PageQuery) => mockUnitedPassDataSource.getPolicies(query)
    : async (query?: PageQuery) => parsePolicies(
        await serverFetch<unknown>(withPageQuery("/admin/policies", query)),
      ),
  getPolicyDetail: USE_MOCK_DATA_SOURCE
    ? (policyId) => mockUnitedPassDataSource.getPolicyDetail(policyId)
    : (policyId) => nullableServerQuery(
        `/admin/policies/${encodeURIComponent(policyId)}`,
        parsePolicyDetail,
      ),
  getAuditEvents: USE_MOCK_DATA_SOURCE
    ? (query?: AuditQuery) => mockUnitedPassDataSource.getAuditEvents(query)
    : async (query?: AuditQuery) => parseAuditEvents(
        await serverFetch<unknown>(withAuditQuery("/admin/audit-events", query)),
      ),
};

export async function getPublicLoginProviders() {
  if (USE_MOCK_DATA_SOURCE) return [];
  try {
    return parsePublicLoginProviders(await serverFetch<unknown>("/auth/providers"));
  } catch (error) {
    if (isApiError(error) && error.kind === "not_found") return [];
    throw error;
  }
}
