//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Browser-side mutating API commands
//

"use client";

import type { UnitedPassCommands } from "@/lib/api/united-pass-data-source";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";
import { USE_MOCK_DATA_SOURCE } from "@/lib/api/data-source-mode";
import { browserFetch } from "@/lib/api/browser/browser-http-client";
import {
  parseDecisionResponse,
  parseDepartmentDetail,
  parseDirectorySyncResult,
  parsePasskeyEnrollment,
  parsePasskeyEnrollmentConfirmation,
  parseProviderDetail,
  parseReauthenticationGrant,
  parseReauthenticationOutcome,
  parseRevokedSessionCount,
  parseSecuritySummary,
  parseTotpEnrollment,
  parseTotpEnrollmentConfirmation,
} from "@/lib/api/response-validators";

/**
 * Browser-side command layer.
 *
 * Client Components import mutations from this module instead of the mock
 * data source directly. Seams migrate from the mock source to real HTTP
 * one at a time (frontend-freeze-v1.md §5): migrated seams call
 * `browser-http-client.ts` (same-origin credentials; the `up_csrf` cookie
 * is attached as `X-CSRF-Token` on every write) and narrow the untrusted
 * response onto the frozen contract types; unmigrated seams keep the mock
 * source until their backend contract lands.
 *
 * Migrated seams: decideConsent, revokeGrant, account reauthentication,
 * password/TOTP/passkey security operations, own-session revocation, logout,
 * and all Phase 5 identity/workforce mutations.
 *
 * See ADR-0004 for the full architecture.
 */
export const browserCommands: UnitedPassCommands = {
  createOAuthClient: (input) => mockUnitedPassDataSource.createOAuthClient(input),
  createApplicationWithInitialClient: (input) =>
    mockUnitedPassDataSource.createApplicationWithInitialClient(input),
  decideConsent: USE_MOCK_DATA_SOURCE
    ? (requestId, decision) => mockUnitedPassDataSource.decideConsent(requestId, decision)
    : async (requestId, decision) =>
        parseDecisionResponse(
          await browserFetch<unknown>(
            `/authorization/requests/${encodeURIComponent(requestId)}/decision`,
            { method: "POST", body: { decision } },
          ),
        ),
  revokeGrant: USE_MOCK_DATA_SOURCE
    ? (grantId) => mockUnitedPassDataSource.revokeGrant(grantId)
    : async (grantId) => {
        // Idempotent backend revocation; 204 carries no body.
        await browserFetch<unknown>(
          `/me/authorized-applications/${encodeURIComponent(grantId)}`,
          { method: "DELETE" },
        );
      },
  rotateClientSecret: (applicationId, clientId) =>
    mockUnitedPassDataSource.rotateClientSecret(applicationId, clientId),
  updateApplicationStatus: (applicationId, status) =>
    mockUnitedPassDataSource.updateApplicationStatus(applicationId, status),
  deleteApplication: (applicationId) =>
    mockUnitedPassDataSource.deleteApplication(applicationId),
  updateApplication: (applicationId, input) =>
    mockUnitedPassDataSource.updateApplication(applicationId, input),

  updateProfile: (input) => mockUnitedPassDataSource.updateProfile(input),
  uploadAvatar: (file) => mockUnitedPassDataSource.uploadAvatar(file),
  requestEmailChange: (email) => mockUnitedPassDataSource.requestEmailChange(email),
  verifyEmailChange: (requestId, code) =>
    mockUnitedPassDataSource.verifyEmailChange(requestId, code),
  requestPhoneChange: (phone) => mockUnitedPassDataSource.requestPhoneChange(phone),
  verifyPhoneChange: (requestId, code) =>
    mockUnitedPassDataSource.verifyPhoneChange(requestId, code),
  changePassword: USE_MOCK_DATA_SOURCE
    ? (newPassword, reauthToken) => mockUnitedPassDataSource.changePassword(newPassword, reauthToken)
    : async (newPassword, reauthToken, options) => {
        await browserFetch<unknown>("/me/security/password", {
          method: "POST",
          reauthToken,
          signal: options?.signal,
          body: { newPassword },
        });
      },
  beginTotpEnrollment: USE_MOCK_DATA_SOURCE
    ? (reauthToken) => mockUnitedPassDataSource.beginTotpEnrollment(reauthToken)
    : async (reauthToken, options) => parseTotpEnrollment(
        await browserFetch<unknown>("/me/security/totp/enrollment", {
          method: "POST",
          reauthToken,
          signal: options?.signal,
        }),
      ),
  confirmTotpEnrollment: USE_MOCK_DATA_SOURCE
    ? (input) => mockUnitedPassDataSource.confirmTotpEnrollment(input)
    : async (input) => {
        parseTotpEnrollmentConfirmation(
          await browserFetch<unknown>("/me/security/totp/enrollment/confirm", {
            method: "POST",
            body: input,
          }),
        );
      },
  cancelTotpEnrollment: USE_MOCK_DATA_SOURCE
    ? (enrollmentToken) => mockUnitedPassDataSource.cancelTotpEnrollment(enrollmentToken)
    : async (enrollmentToken) => {
        await browserFetch<unknown>("/me/security/totp/enrollment/cancel", {
          method: "POST",
          body: { enrollmentToken },
        });
      },
  removeTotp: USE_MOCK_DATA_SOURCE
    ? (reauthToken) => mockUnitedPassDataSource.removeTotp(reauthToken)
    : async (reauthToken, options) => parseSecuritySummary(
        await browserFetch<unknown>("/me/security/totp", {
          method: "DELETE",
          reauthToken,
          signal: options?.signal,
        }),
      ),
  requestReauthentication: USE_MOCK_DATA_SOURCE
    ? (input) => mockUnitedPassDataSource.requestReauthentication(input)
    : async (input, options) => parseReauthenticationOutcome(
        await browserFetch<unknown>("/auth/reauthentication", {
          method: "POST",
          signal: options?.signal,
          body: {
            action: input.action,
            applicationId: "",
            clientId: "",
            target: input.target,
            password: input.password,
          },
        }),
      ),
  completeReauthenticationMfa: USE_MOCK_DATA_SOURCE
    ? (input) => mockUnitedPassDataSource.completeReauthenticationMfa(input)
    : async (input, options) => parseReauthenticationGrant(
        await browserFetch<unknown>("/auth/reauthentication/mfa", {
          method: "POST",
          signal: options?.signal,
          body: {
            reauthToken: input.reauthToken,
            method: input.method,
            code: input.code ?? "",
            ...(input.passkeyAssertion !== undefined && {
              passkeyAssertion: input.passkeyAssertion,
            }),
          },
        }),
      ),
  startPasskeyEnrollment: USE_MOCK_DATA_SOURCE
    ? (reauthToken) => mockUnitedPassDataSource.startPasskeyEnrollment(reauthToken)
    : async (reauthToken, options) => parsePasskeyEnrollment(
        await browserFetch<unknown>("/me/security/passkeys/enrollment", {
          method: "POST",
          reauthToken,
          signal: options?.signal,
        }),
      ),
  completePasskeyEnrollment: USE_MOCK_DATA_SOURCE
    ? (input) => mockUnitedPassDataSource.completePasskeyEnrollment(input)
    : async (input, options) => parsePasskeyEnrollmentConfirmation(
        await browserFetch<unknown>("/me/security/passkeys/enrollment/confirm", {
          method: "POST",
          signal: options?.signal,
          body: {
            enrollmentToken: input.enrollmentToken,
            publicKeyCredential: input.publicKeyCredential,
            passkeyName: input.passkeyName,
          },
        }),
        input.passkeyId,
      ),
  cancelPasskeyEnrollment: USE_MOCK_DATA_SOURCE
    ? (enrollmentToken) => mockUnitedPassDataSource.cancelPasskeyEnrollment(enrollmentToken)
    : async (enrollmentToken) => {
        await browserFetch<unknown>("/me/security/passkeys/enrollment/cancel", {
          method: "POST",
          body: { enrollmentToken },
        });
      },
  removePasskey: USE_MOCK_DATA_SOURCE
    ? (passkeyId, reauthToken) => mockUnitedPassDataSource.removePasskey(passkeyId, reauthToken)
    : async (passkeyId, reauthToken, options) => parseSecuritySummary(
        await browserFetch<unknown>(
          `/me/security/passkeys/${encodeURIComponent(passkeyId)}`,
          { method: "DELETE", reauthToken, signal: options?.signal },
        ),
      ),
  generateRecoveryCodes: () => mockUnitedPassDataSource.generateRecoveryCodes(),
  revokeOtherSessions: USE_MOCK_DATA_SOURCE
    ? () => mockUnitedPassDataSource.revokeOtherSessions()
    : async () => parseRevokedSessionCount(
        await browserFetch<unknown>("/me/sessions", { method: "DELETE" }),
      ),
  logout: USE_MOCK_DATA_SOURCE
    ? () => mockUnitedPassDataSource.logout()
    : async () => {
        await browserFetch<unknown>("/auth/session", { method: "DELETE" });
      },
  revokeOwnSession: USE_MOCK_DATA_SOURCE
    ? (sessionId) => mockUnitedPassDataSource.revokeOwnSession(sessionId)
    : async (sessionId) => {
        await browserFetch<unknown>(`/me/sessions/${encodeURIComponent(sessionId)}`, {
          method: "DELETE",
        });
      },

  // Admin user management
  updateUserStatus: USE_MOCK_DATA_SOURCE
    ? (userId, status) => mockUnitedPassDataSource.updateUserStatus(userId, status)
    : async (userId, status, reauthToken, options) => {
        await browserFetch<unknown>(
          `/admin/users/${encodeURIComponent(userId)}/${status === "active" ? "enable" : "disable"}`,
          {
            method: "POST",
            reauthToken: status === "disabled" ? reauthToken : undefined,
            signal: options?.signal,
            ...(status === "disabled" && { body: { revokeSessions: true } }),
          },
        );
      },
  revokeUserSession: USE_MOCK_DATA_SOURCE
    ? (userId, sessionId) => mockUnitedPassDataSource.revokeUserSession(userId, sessionId)
    : async (userId, sessionId) => {
        await browserFetch<unknown>(
          `/admin/users/${encodeURIComponent(userId)}/sessions/${encodeURIComponent(sessionId)}`,
          { method: "DELETE" },
        );
      },
  revokeUserSessions: USE_MOCK_DATA_SOURCE
    ? (userId) => mockUnitedPassDataSource.revokeUserSessions(userId, "")
    : async (userId, reauthToken, options) => {
        await browserFetch<unknown>(
          `/admin/users/${encodeURIComponent(userId)}/sessions`,
          { method: "DELETE", reauthToken, signal: options?.signal },
        );
      },
  linkEmployeeProfile: USE_MOCK_DATA_SOURCE
    ? (input) => mockUnitedPassDataSource.linkEmployeeProfile(input)
    : async (input) => {
        await browserFetch<unknown>("/admin/employees/link", { method: "POST", body: input });
      },
  updateEmployeeProfile: USE_MOCK_DATA_SOURCE
    ? (userId, input) => mockUnitedPassDataSource.updateEmployeeProfile(userId, input)
    : async (userId, input) => {
        await browserFetch<unknown>(
          `/admin/users/${encodeURIComponent(userId)}/employee-profile`,
          { method: "PUT", body: input },
        );
      },
  offboardEmployee: USE_MOCK_DATA_SOURCE
    ? (userId) => mockUnitedPassDataSource.offboardEmployee(userId, "")
    : async (userId, reauthToken, options) => {
        await browserFetch<unknown>(
          `/admin/users/${encodeURIComponent(userId)}/offboarding`,
          { method: "POST", reauthToken, signal: options?.signal },
        );
      },
  createDepartment: USE_MOCK_DATA_SOURCE
    ? (input) => mockUnitedPassDataSource.createDepartment(input)
    : async (input) => parseDepartmentDetail(
        await browserFetch<unknown>("/admin/departments", { method: "POST", body: input }),
      ),
  updateDepartment: USE_MOCK_DATA_SOURCE
    ? (departmentId, input) => mockUnitedPassDataSource.updateDepartment(departmentId, input)
    : async (departmentId, input) => parseDepartmentDetail(
        await browserFetch<unknown>(
          `/admin/departments/${encodeURIComponent(departmentId)}`,
          { method: "PATCH", body: input },
        ),
      ),
  deleteDepartment: USE_MOCK_DATA_SOURCE
    ? (departmentId) => mockUnitedPassDataSource.deleteDepartment(departmentId)
    : async (departmentId) => {
        await browserFetch<unknown>(
          `/admin/departments/${encodeURIComponent(departmentId)}`,
          { method: "DELETE" },
        );
      },

  // Policy management
  savePolicyDraft: (input) => mockUnitedPassDataSource.savePolicyDraft(input),
  publishPolicy: (policyId) => mockUnitedPassDataSource.publishPolicy(policyId),
  simulatePolicy: (input) => mockUnitedPassDataSource.simulatePolicy(input),

  // Provider management
  syncProviderDirectory: USE_MOCK_DATA_SOURCE
    ? (providerId) => mockUnitedPassDataSource.syncProviderDirectory(providerId)
    : async (providerId) => parseDirectorySyncResult(
        await browserFetch<unknown>(
          `/admin/identity-providers/${encodeURIComponent(providerId)}/directory-syncs`,
          { method: "POST" },
        ),
      ),
  updateProviderLogin: USE_MOCK_DATA_SOURCE
    ? (providerId, enabled) => mockUnitedPassDataSource.updateProviderLogin(providerId, enabled, "")
    : async (providerId, enabled, reauthToken, options) => parseProviderDetail(
        await browserFetch<unknown>(
          `/admin/identity-providers/${encodeURIComponent(providerId)}/${enabled ? "enable" : "disable"}`,
          { method: "POST", reauthToken, signal: options?.signal },
        ),
      ),
  resolveSyncConflict: USE_MOCK_DATA_SOURCE
    ? (conflictId, userId) => mockUnitedPassDataSource.resolveSyncConflict(conflictId, userId, "")
    : async (conflictId, userId, reauthToken, options) => {
        await browserFetch<unknown>(
          `/admin/identity-providers/sync-conflicts/${encodeURIComponent(conflictId)}/resolve`,
          { method: "POST", reauthToken, signal: options?.signal, body: { userId } },
        );
      },
  ignoreSyncConflict: USE_MOCK_DATA_SOURCE
    ? (conflictId) => mockUnitedPassDataSource.ignoreSyncConflict(conflictId)
    : async (conflictId) => {
        await browserFetch<unknown>(
          `/admin/identity-providers/sync-conflicts/${encodeURIComponent(conflictId)}/ignore`,
          { method: "POST" },
        );
      },

  // Audit export
  exportAuditEvents: (query) => mockUnitedPassDataSource.exportAuditEvents(query),
};
