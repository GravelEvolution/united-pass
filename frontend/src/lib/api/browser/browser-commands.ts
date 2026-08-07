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

/**
 * Browser-side command layer.
 *
 * Client Components import mutations from this module instead of the mock
 * data source directly. When the real backend API is available, this module
 * will use `browser-http-client.ts` to make authenticated HTTP requests with
 * CSRF protection, and the mock import will be removed.
 *
 * See ADR-0004 for the full architecture.
 */
export const browserCommands: UnitedPassCommands = {
  createOAuthClient: (input) => mockUnitedPassDataSource.createOAuthClient(input),
  createApplicationWithInitialClient: (input) =>
    mockUnitedPassDataSource.createApplicationWithInitialClient(input),
  decideConsent: (requestId, decision) =>
    mockUnitedPassDataSource.decideConsent(requestId, decision),
  revokeGrant: (grantId) => mockUnitedPassDataSource.revokeGrant(grantId),
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
  startPasskeyEnrollment: () => mockUnitedPassDataSource.startPasskeyEnrollment(),
  completePasskeyEnrollment: (attestation) =>
    mockUnitedPassDataSource.completePasskeyEnrollment(attestation),
  removePasskey: (credentialId) => mockUnitedPassDataSource.removePasskey(credentialId),
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
