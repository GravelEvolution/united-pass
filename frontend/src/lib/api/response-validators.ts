//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Runtime narrowing of untrusted HTTP response bodies onto the
//              frozen frontend contract types
//

import type {
  ConsentRequest,
  ConsentResolution,
  ConsentScope,
} from "@/features/authorization/types";
import type { AuthorizedApplication } from "@/features/account/types";
import type { CurrentUser, EmployeeProfile, UserPersona } from "@/types/identity";

/**
 * Response body validators for the real HTTP seams.
 *
 * Backend responses are untrusted runtime data (AGENTS.md §16): every seam
 * narrows the parsed JSON onto the frozen contract types before it reaches
 * a page or component. A malformed body is a contract violation and throws
 * instead of rendering partial or fabricated facts; server queries surface
 * it through the route error boundary, browser commands through their error
 * states.
 *
 * The ConsentResolution union is frozen (frontend-freeze-v1.md, ADR-0005
 * §12): these parsers accept exactly its members and nothing else.
 */

export class ApiResponseShapeError extends Error {
  constructor(contract: string) {
    super(`API response does not match the ${contract} contract`);
    this.name = "ApiResponseShapeError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== "string") {
    throw new ApiResponseShapeError(field);
  }
  return value;
}

function optionalString(record: Record<string, unknown>, field: string): string | undefined {
  const value = record[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    throw new ApiResponseShapeError(field);
  }
  return value;
}

function requireBoolean(record: Record<string, unknown>, field: string): boolean {
  const value = record[field];
  if (typeof value !== "boolean") {
    throw new ApiResponseShapeError(field);
  }
  return value;
}

function requireStringArray(record: Record<string, unknown>, field: string): string[] {
  const value = record[field];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new ApiResponseShapeError(field);
  }
  return value as string[];
}

// --- ConsentResolution ---

function parseConsentScope(value: unknown): ConsentScope {
  if (!isRecord(value)) throw new ApiResponseShapeError("ConsentScope");
  return {
    scope: requireString(value, "scope"),
    label: requireString(value, "label"),
    description: requireString(value, "description"),
  };
}

function parseConsentRequest(value: unknown): ConsentRequest {
  if (!isRecord(value)) throw new ApiResponseShapeError("ConsentRequest");
  const scopesValue = value.scopes;
  if (!Array.isArray(scopesValue)) throw new ApiResponseShapeError("ConsentRequest.scopes");
  return {
    requestId: requireString(value, "requestId"),
    applicationName: requireString(value, "applicationName"),
    applicationDescription: requireString(value, "applicationDescription"),
    applicationOwner: requireString(value, "applicationOwner"),
    redirectHost: requireString(value, "redirectHost"),
    scopes: scopesValue.map(parseConsentScope),
  };
}

/**
 * Narrows an untrusted resolution body onto the frozen ConsentResolution
 * union. Unknown statuses are rejected: the page must never render a union
 * member the contract does not define.
 */
export function parseConsentResolution(value: unknown): ConsentResolution {
  if (!isRecord(value)) throw new ApiResponseShapeError("ConsentResolution");
  const status = value.status;

  switch (status) {
    case "valid":
      return { status, request: parseConsentRequest(value.request) };
    case "expired":
      return {
        status,
        requestId: requireString(value, "requestId"),
        expiredAt: requireString(value, "expiredAt"),
      };
    case "client_not_found":
    case "unauthenticated":
      return { status, requestId: requireString(value, "requestId") };
    case "redirect_mismatch":
      return {
        status,
        requestId: requireString(value, "requestId"),
        attemptedRedirect: requireString(value, "attemptedRedirect"),
      };
    case "scope_not_allowed":
      return {
        status,
        requestId: requireString(value, "requestId"),
        disallowedScopes: requireStringArray(value, "disallowedScopes"),
      };
    case "already_authorized":
      return {
        status,
        requestId: requireString(value, "requestId"),
        applicationName: requireString(value, "applicationName"),
        redirectHost: requireString(value, "redirectHost"),
      };
    default:
      throw new ApiResponseShapeError("ConsentResolution.status");
  }
}

/** Narrows the decision response: the provider-verified callback URL. */
export function parseDecisionResponse(value: unknown): { redirectUrl: string } {
  if (!isRecord(value)) throw new ApiResponseShapeError("ConsentDecisionResponse");
  const redirectUrl = value.redirectUrl;
  if (typeof redirectUrl !== "string" || redirectUrl.length === 0) {
    throw new ApiResponseShapeError("ConsentDecisionResponse.redirectUrl");
  }
  return { redirectUrl };
}

// --- AuthorizedApplication ---

function parseAuthorizedApplication(value: unknown): AuthorizedApplication {
  if (!isRecord(value)) throw new ApiResponseShapeError("AuthorizedApplication");

  const clientType = value.clientType;
  if (clientType !== "public" && clientType !== "confidential") {
    throw new ApiResponseShapeError("AuthorizedApplication.clientType");
  }
  const status = value.status;
  if (status !== "active" && status !== "revoked") {
    throw new ApiResponseShapeError("AuthorizedApplication.status");
  }
  const lastUsedAt = value.lastUsedAt;
  if (lastUsedAt !== null && typeof lastUsedAt !== "string") {
    throw new ApiResponseShapeError("AuthorizedApplication.lastUsedAt");
  }

  return {
    grantId: requireString(value, "grantId"),
    applicationId: requireString(value, "applicationId"),
    applicationName: requireString(value, "applicationName"),
    applicationOwner: requireString(value, "applicationOwner"),
    clientType,
    grantedAt: requireString(value, "grantedAt"),
    lastUsedAt,
    scopes: requireStringArray(value, "scopes"),
    hasOfflineAccess: requireBoolean(value, "hasOfflineAccess"),
    status,
  };
}

/** Narrows the authorized application listing body. */
export function parseAuthorizedApplications(value: unknown): AuthorizedApplication[] {
  if (!Array.isArray(value)) throw new ApiResponseShapeError("AuthorizedApplication[]");
  return value.map(parseAuthorizedApplication);
}

// --- CurrentUser ---

function parseUserPersona(value: unknown): UserPersona {
  if (value !== "consumer" && value !== "employee") {
    throw new ApiResponseShapeError("UserPersona");
  }
  return value;
}

function parseEmployeeProfile(value: unknown): EmployeeProfile | undefined {
  if (value === undefined || value === null) return undefined;
  if (!isRecord(value)) throw new ApiResponseShapeError("EmployeeProfile");
  return {
    employeeId: requireString(value, "employeeId"),
    departmentName: requireString(value, "departmentName"),
    title: requireString(value, "title"),
  };
}

/** Narrows the GET /api/v1/me body onto the frozen CurrentUser type. */
export function parseCurrentUser(value: unknown): CurrentUser {
  if (!isRecord(value)) throw new ApiResponseShapeError("CurrentUser");
  const personasValue = value.personas;
  if (!Array.isArray(personasValue)) throw new ApiResponseShapeError("CurrentUser.personas");

  const user: CurrentUser = {
    userId: requireString(value, "userId"),
    displayName: requireString(value, "displayName"),
    email: requireString(value, "email"),
    phoneMasked: requireString(value, "phoneMasked"),
    personas: personasValue.map(parseUserPersona),
  };

  const nickname = optionalString(value, "nickname");
  if (nickname !== undefined) user.nickname = nickname;
  const avatarUrl = optionalString(value, "avatarUrl");
  if (avatarUrl !== undefined) user.avatarUrl = avatarUrl;
  const employeeProfile = parseEmployeeProfile(value.employeeProfile);
  if (employeeProfile !== undefined) user.employeeProfile = employeeProfile;

  return user;
}
