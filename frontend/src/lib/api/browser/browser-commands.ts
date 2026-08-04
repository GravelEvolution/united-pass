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
  createApplication: (input) => mockUnitedPassDataSource.createApplication(input),
  createOAuthClient: (input) => mockUnitedPassDataSource.createOAuthClient(input),
  createApplicationWithInitialClient: (input) =>
    mockUnitedPassDataSource.createApplicationWithInitialClient(input),
  decideConsent: (requestId, decision) =>
    mockUnitedPassDataSource.decideConsent(requestId, decision),
  revokeGrant: (grantId) => mockUnitedPassDataSource.revokeGrant(grantId),
  rotateClientSecret: (clientId) => mockUnitedPassDataSource.rotateClientSecret(clientId),
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
};
