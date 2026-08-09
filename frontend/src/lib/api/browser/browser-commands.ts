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
  parsePasskeyEnrollment,
  parsePasskeyEnrollmentConfirmation,
  parseReauthenticationGrant,
  parseReauthenticationOutcome,
  parseSecuritySummary,
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
 * Migrated seams: decideConsent, revokeGrant.
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
  changePassword: (currentPassword, newPassword) =>
    mockUnitedPassDataSource.changePassword(currentPassword, newPassword),
  enrollTotp: () => mockUnitedPassDataSource.enrollTotp(),
  confirmTotpEnrollment: (code) => mockUnitedPassDataSource.confirmTotpEnrollment(code),
  removeTotp: () => mockUnitedPassDataSource.removeTotp(),
  requestReauthentication: USE_MOCK_DATA_SOURCE
    ? (input) => mockUnitedPassDataSource.requestReauthentication(input)
    : async (input) => parseReauthenticationOutcome(
        await browserFetch<unknown>("/auth/reauthentication", {
          method: "POST",
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
    : async (input) => parseReauthenticationGrant(
        await browserFetch<unknown>("/auth/reauthentication/mfa", {
          method: "POST",
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
    : async (reauthToken) => parsePasskeyEnrollment(
        await browserFetch<unknown>("/me/security/passkeys/enrollment", {
          method: "POST",
          reauthToken,
        }),
      ),
  completePasskeyEnrollment: USE_MOCK_DATA_SOURCE
    ? (input) => mockUnitedPassDataSource.completePasskeyEnrollment(input)
    : async (input) => parsePasskeyEnrollmentConfirmation(
        await browserFetch<unknown>("/me/security/passkeys/enrollment/confirm", {
          method: "POST",
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
    : async (passkeyId, reauthToken) => parseSecuritySummary(
        await browserFetch<unknown>(
          `/me/security/passkeys/${encodeURIComponent(passkeyId)}`,
          { method: "DELETE", reauthToken },
        ),
      ),
  generateRecoveryCodes: () => mockUnitedPassDataSource.generateRecoveryCodes(),
  revokeOtherSessions: () => mockUnitedPassDataSource.revokeOtherSessions(),
  logout: () => mockUnitedPassDataSource.logout(),
  revokeSession: (sessionId) => mockUnitedPassDataSource.revokeSession(sessionId),

  // Admin user management
  updateUserStatus: (userId, status) =>
    mockUnitedPassDataSource.updateUserStatus(userId, status),
  revokeUserSessions: (userId) =>
    mockUnitedPassDataSource.revokeUserSessions(userId),
  linkEmployeeProfile: (input) =>
    mockUnitedPassDataSource.linkEmployeeProfile(input),
  offboardEmployee: (userId) =>
    mockUnitedPassDataSource.offboardEmployee(userId),

  // Policy management
  savePolicyDraft: (input) => mockUnitedPassDataSource.savePolicyDraft(input),
  publishPolicy: (policyId) => mockUnitedPassDataSource.publishPolicy(policyId),
  simulatePolicy: (input) => mockUnitedPassDataSource.simulatePolicy(input),

  // Provider management
  syncProviderDirectory: (providerId) => mockUnitedPassDataSource.syncProviderDirectory(providerId),
  resolveSyncConflict: (conflictId, userId) => mockUnitedPassDataSource.resolveSyncConflict(conflictId, userId),
  ignoreSyncConflict: (conflictId) => mockUnitedPassDataSource.ignoreSyncConflict(conflictId),

  // Audit export
  exportAuditEvents: (query) => mockUnitedPassDataSource.exportAuditEvents(query),
};
