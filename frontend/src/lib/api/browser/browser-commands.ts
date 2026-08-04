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
};
