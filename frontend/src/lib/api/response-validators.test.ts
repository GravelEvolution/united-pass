//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Unit tests for the HTTP response body validators
//

import { describe, it, expect } from "vitest";
import {
  ApiResponseShapeError,
  parseAccountDeletion,
  parseAuthorizedApplications,
  parseAuditEvents,
  parseAuditExport,
  parseConsentResolution,
  parseCurrentUser,
  parseDecisionResponse,
  parseDepartmentDetail,
  parseDepartments,
  parseEmployeeDetail,
  parseEmployees,
  parseDirectorySyncHistory,
  parseDirectorySyncResult,
  parseIdentityProviders,
  parseManagedUsers,
  parseMfaRequiredResponse,
  parsePasskeyEnrollment,
  parsePasskeyEnrollmentConfirmation,
  parsePersonalDataExport,
  parsePolicies,
  parsePolicyDetail,
  parsePolicySimulation,
  parsePermissionCapabilities,
  parseProviderDetail,
  parsePublicLoginProviders,
  parseReauthenticationOutcome,
  parseRevokedSessionCount,
  parseSecuritySummary,
  parseTotpEnrollment,
  parseTotpEnrollmentConfirmation,
  parseSyncConflicts,
  parseUserSessions,
  parseUserDetail,
} from "./response-validators";

describe("P8 privacy-rights validators", () => {
  it("narrows export and deletion lifecycle responses", () => {
    expect(parsePersonalDataExport({
      exportId: "pexp_0123456789abcdef",
      status: "completed",
      requestedAt: "2026-08-11T00:00:00Z",
      completedAt: "2026-08-11T00:00:01Z",
      expiresAt: "2026-08-11T00:15:01Z",
      downloadUrl: "/api/v1/me/data-exports/pexp_0123456789abcdef/download",
      totalSections: 6,
    }).totalSections).toBe(6);

    expect(parseAccountDeletion({ status: "none" })).toEqual({ status: "none" });
    expect(parseAccountDeletion({
      deletionId: "del_0123456789abcdef",
      status: "pending",
      requestedAt: "2026-08-11T00:00:00Z",
      executeAfter: "2026-09-10T00:00:00Z",
      cancelledAt: null,
      completedAt: null,
    }).status).toBe("pending");
  });

  it("fails closed on unknown lifecycle states and missing nullable fields", () => {
    expect(() => parsePersonalDataExport({
      exportId: "pexp_0123456789abcdef", status: "ready", requestedAt: "x",
      completedAt: null, expiresAt: null, downloadUrl: null, totalSections: 0,
    })).toThrow(ApiResponseShapeError);
    expect(() => parseAccountDeletion({
      deletionId: "del_0123456789abcdef", status: "pending",
      requestedAt: "x", executeAfter: "y", completedAt: null,
    })).toThrow(ApiResponseShapeError);
  });
});

describe("P7 policy and audit validators", () => {
  const policy = {
    policyId: "pol_0123456789abcdef",
    name: "应用管理员",
    resource: "application:*",
    version: 2,
    status: "draft",
    updatedBy: "管理员",
    updatedAt: "2026-08-11T00:00:00Z",
  } as const;

  it("narrows policy pages, immutable detail and simulation unions", () => {
    expect(parsePolicies({ items: [policy], page: { nextCursor: null, hasMore: false } }).items[0]).toEqual(policy);
    expect(parsePolicyDetail({
      ...policy,
      description: "说明",
      action: "application.manage",
      effect: "allow",
      principals: [{ attribute: "department", operator: "eq", value: "Identity" }],
      conditions: [],
      versionHistory: [{ version: 2, status: "draft", updatedBy: "管理员", updatedAt: policy.updatedAt, changeSummary: "编辑草稿" }],
    }).principals[0].operator).toBe("eq");
    expect(parsePolicySimulation({
      decision: "no_match", matchedPolicyId: null, matchedPolicyName: null,
      evaluatedAt: policy.updatedAt, reasons: ["未匹配"],
    }).decision).toBe("no_match");
    expect(() => parsePolicySimulation({
      decision: "maybe", matchedPolicyId: null, matchedPolicyName: null,
      evaluatedAt: policy.updatedAt, reasons: [],
    })).toThrow(ApiResponseShapeError);
  });

  it("accepts only redacted audit rows and durable export states", () => {
    expect(parseAuditEvents({
      items: [{
        eventId: "evt_1", eventType: "policy.published", actorName: "管理员",
        actorId: "user_1", targetLabel: "policy_id", targetId: policy.policyId,
        occurredAt: policy.updatedAt, result: "success", requestId: "req_1",
        details: "policy.publish",
      }],
      page: { nextCursor: null, hasMore: false },
    }).items[0].eventType).toBe("policy.published");
    expect(parseAuditExport({
      exportId: "exp_1", status: "processing", downloadUrl: null,
      requestedAt: policy.updatedAt, completedAt: null, totalEvents: 0,
    }).status).toBe("processing");
    expect(() => parseAuditExport({
      exportId: "exp_1", status: "ready", downloadUrl: null,
      requestedAt: policy.updatedAt, completedAt: null, totalEvents: 0,
    })).toThrow(ApiResponseShapeError);
  });
});

describe("P6 Provider validators", () => {
  const provider = {
    providerId: "provider_feishu",
    displayName: "飞书",
    vendor: "feishu",
    integrationLabel: "OAuth 2.0 + 通讯录 OpenAPI",
    status: "active",
    loginEnabled: true,
    linkedUserCount: 1,
    updatedAt: "2026-08-11T00:00:00Z",
  };
  const sync = {
    syncId: "sync_A",
    providerId: "provider_feishu",
    startedAt: "2026-08-11T00:00:00Z",
    completedAt: null,
    status: "running",
    departmentsAdded: 0,
    departmentsUpdated: 0,
    employeesAdded: 0,
    employeesUpdated: 0,
    employeesOffboarded: 0,
    conflictsDetected: 0,
  };

  it("narrows Provider list/detail and accepts durable in-flight jobs", () => {
    expect(parseIdentityProviders({
      items: [provider],
      page: { nextCursor: null, hasMore: false },
    }).items[0]).toEqual(provider);
    expect(parseDirectorySyncResult(sync)).toEqual({
      syncId: sync.syncId,
      startedAt: sync.startedAt,
      completedAt: null,
      status: "running",
      departmentsAdded: 0,
      departmentsUpdated: 0,
      employeesAdded: 0,
      employeesUpdated: 0,
      employeesOffboarded: 0,
      conflictsDetected: 0,
    });
    expect(parseProviderDetail({
      ...provider,
      appId: "cli_test",
      secretConfigured: true,
      callbackUrl: "https://id.example.test/api/v1/auth/providers/feishu/callback",
      contactScope: "contact:user.base:readonly",
      lastValidatedAt: null,
      lastSyncAt: sync.startedAt,
      lastSyncResult: sync,
    }).lastSyncResult?.status).toBe("running");
    expect(() => parseIdentityProviders({
      items: [{ ...provider, linkedUserCount: -1 }],
      page: { nextCursor: null, hasMore: false },
    })).toThrow(ApiResponseShapeError);
  });

  it("narrows history, explicit-link conflicts and public login availability", () => {
    expect(parseDirectorySyncHistory([{ ...sync, summary: "同步执行中" }])[0]).toMatchObject({
      providerId: "provider_feishu",
      completedAt: null,
      status: "running",
    });
    const conflict = {
      conflictId: "conflict_A",
      providerId: "provider_feishu",
      externalSubject: "ou_A",
      externalName: "Alice",
      externalEmail: "alice@example.test",
      matchedUserId: "user_A",
      matchedUserName: "Alice",
      matchReason: "email",
      status: "pending",
      detectedAt: "2026-08-11T00:00:00Z",
    };
    expect(parseSyncConflicts([conflict])).toEqual([conflict]);
    expect(() => parseSyncConflicts([{ ...conflict, matchReason: "automatic" }])).toThrow(ApiResponseShapeError);
    expect(parsePublicLoginProviders({ items: [{
      providerId: "provider_feishu", displayName: "飞书", loginEnabled: true,
    }] })).toHaveLength(1);
  });
});

describe("P5 identity and workforce validators", () => {
  const page = { nextCursor: null, hasMore: false };

  it("fails closed when any permission capability is missing or malformed", () => {
    const permissions = Object.fromEntries([
      "userRead", "userDisable", "employeeManage", "employeeOffboard", "departmentManage",
      "applicationRead", "applicationManage", "applicationSecretRotate", "policyRead",
      "policyManage", "policyPublish", "auditRead", "auditExport", "providerRead", "providerManage",
    ].map((key) => [key, true]));
    expect(parsePermissionCapabilities(permissions)).toEqual(permissions);
    expect(() => parsePermissionCapabilities({ ...permissions, userRead: "yes" })).toThrow(ApiResponseShapeError);
    const missing = { ...permissions };
    delete missing.userRead;
    expect(() => parsePermissionCapabilities(missing)).toThrow(ApiResponseShapeError);
  });

  it("narrows user pages and rejects cursor/status drift", () => {
    const user = {
      userId: "user_A", displayName: "Alice", email: "a@example.com",
      personaLabel: "外部用户", status: "active", lastActiveAt: "2026-08-11T00:00:00Z",
    };
    expect(parseManagedUsers({ items: [user], page })).toEqual({ items: [user], page });
    expect(() => parseManagedUsers({ items: [{ ...user, status: "deleted" }], page })).toThrow(ApiResponseShapeError);
    expect(() => parseManagedUsers({ items: [user], page: { nextCursor: 1, hasMore: true } })).toThrow(ApiResponseShapeError);
  });

  it("narrows complete user detail arrays without fabricating optional employee data", () => {
    const detail = {
      userId: "user_A", displayName: "Alice", email: "a@example.com", phoneMasked: "",
      personaLabel: "外部用户", status: "active", lastActiveAt: "2026-08-11T00:00:00Z",
      personas: ["consumer"],
      linkedIdentities: [{ providerId: "idp_1", providerName: "ZITADEL", externalSubject: "subject", linkedAt: "2026-08-11T00:00:00Z" }],
      activeSessions: [{ sessionId: "session_A", deviceName: "Chrome", lastActiveAt: "2026-08-11T00:00:00Z", isCurrent: false }],
      authorizedApplications: [{ applicationName: "App", scopes: ["openid"], grantedAt: "2026-08-11T00:00:00Z", status: "active" }],
      recentAuditEvents: [{ eventId: "event_A", eventType: "user.enabled", actorName: "Admin", actorId: "user_admin", targetLabel: "Alice", targetId: "user_A", occurredAt: "2026-08-11T00:00:00Z", result: "success", requestId: "req_12345678", details: "" }],
    };
    expect(parseUserDetail(detail)).toEqual(detail);
    expect(() => parseUserDetail({ ...detail, activeSessions: [{ sessionId: "x", isCurrent: "false" }] })).toThrow(ApiResponseShapeError);
  });

  it("narrows employee pages and nullable supervisor identity", () => {
    const summary = {
      userId: "user_A", displayName: "Alice", employeeId: "EMP-1",
      departmentName: "Platform", title: "Engineer", status: "active",
    };
    expect(parseEmployees({ items: [summary], page })).toEqual({ items: [summary], page });
    const detail = {
      ...summary, email: "a@example.com", departmentId: "dep_platform",
      supervisorUserId: null, supervisorName: null, onboardedAt: "2026-08-11T00:00:00Z",
      linkedConsumerAccount: true,
    };
    expect(parseEmployeeDetail(detail)).toEqual(detail);
    expect(() => parseEmployeeDetail({ ...detail, supervisorUserId: 42 })).toThrow(ApiResponseShapeError);
  });

  it("narrows department summaries/details and rejects negative counts", () => {
    const summary = { departmentId: "dep_A", name: "Platform", parentName: "", memberCount: 1, ownerName: "Alice" };
    expect(parseDepartments([summary])).toEqual([summary]);
    const detail = {
      ...summary, parentDepartmentId: null, parentName: null, ownerUserId: "user_A",
      childDepartments: [{ departmentId: "dep_B", name: "SRE", memberCount: 0 }],
      members: [{ userId: "user_A", displayName: "Alice", title: "Engineer", employeeId: "EMP-1" }],
    };
    expect(parseDepartmentDetail(detail)).toEqual(detail);
    expect(() => parseDepartmentDetail({ ...detail, memberCount: -1 })).toThrow(ApiResponseShapeError);
  });
});

describe("P4.7 account security validators", () => {
  const session = {
    sessionId: "session-1",
    deviceName: "",
    clientName: "Chrome",
    approximateLocation: null,
    ipAddressMasked: "127.0.0.*",
    lastActiveAt: "2026-08-09T10:00:00Z",
    createdAt: "2026-08-09T09:00:00Z",
    authenticationMethods: ["password", "totp"],
    isCurrent: true,
  };

  it("parses the complete nullable session wire shape", () => {
    expect(parseUserSessions([session])).toEqual([session]);
  });

  it("rejects malformed session fields", () => {
    expect(() => parseUserSessions({ sessions: [] })).toThrow(ApiResponseShapeError);
    expect(() => parseUserSessions([{ ...session, approximateLocation: 1 }])).toThrow(ApiResponseShapeError);
    expect(() => parseUserSessions([{ ...session, authenticationMethods: "password" }])).toThrow(ApiResponseShapeError);
    expect(() => parseUserSessions([{ ...session, createdAt: null }])).toThrow(ApiResponseShapeError);
  });

  it("parses TOTP enrollment only with non-empty secret material and otpauth scheme", () => {
    expect(parseTotpEnrollment({
      enrollmentToken: "enrollment",
      secret: "SECRET",
      otpauthUri: "otpauth://totp/United?secret=SECRET",
    })).toEqual({
      enrollmentToken: "enrollment",
      secret: "SECRET",
      otpauthUri: "otpauth://totp/United?secret=SECRET",
    });
    expect(() => parseTotpEnrollment({
      enrollmentToken: "enrollment",
      secret: "SECRET",
      otpauthUri: "https://example.com/secret",
    })).toThrow(ApiResponseShapeError);
  });

  it("validates TOTP confirmation and non-negative integer revoke counts", () => {
    expect(parseTotpEnrollmentConfirmation({ status: "confirmed" })).toBeUndefined();
    expect(() => parseTotpEnrollmentConfirmation({ status: "pending" })).toThrow(ApiResponseShapeError);
    expect(parseRevokedSessionCount({ revoked: 2 })).toEqual({ revoked: 2 });
    expect(() => parseRevokedSessionCount({ revoked: -1 })).toThrow(ApiResponseShapeError);
    expect(() => parseRevokedSessionCount({ revoked: 1.5 })).toThrow(ApiResponseShapeError);
  });
});

describe("parseConsentResolution", () => {
  it("parses the valid member with the full request", () => {
    const resolution = parseConsentResolution({
      status: "valid",
      request: {
        requestId: "req_01",
        applicationName: "United Workspace",
        applicationDescription: "协作平台",
        applicationOwner: "United",
        redirectHost: "workspace.united.example",
        scopes: [{ scope: "openid", label: "身份", description: "读取基本身份" }],
      },
    });

    expect(resolution).toEqual({
      status: "valid",
      request: {
        requestId: "req_01",
        applicationName: "United Workspace",
        applicationDescription: "协作平台",
        applicationOwner: "United",
        redirectHost: "workspace.united.example",
        scopes: [{ scope: "openid", label: "身份", description: "读取基本身份" }],
      },
    });
  });

  it("parses expired, client_not_found, unauthenticated, redirect_mismatch, scope_not_allowed and already_authorized", () => {
    expect(
      parseConsentResolution({ status: "expired", requestId: "req_01", expiredAt: "2026-08-07T00:00:00Z" }),
    ).toEqual({ status: "expired", requestId: "req_01", expiredAt: "2026-08-07T00:00:00Z" });

    expect(parseConsentResolution({ status: "client_not_found", requestId: "req_02" })).toEqual({
      status: "client_not_found",
      requestId: "req_02",
    });

    expect(parseConsentResolution({ status: "unauthenticated", requestId: "req_03" })).toEqual({
      status: "unauthenticated",
      requestId: "req_03",
    });

    expect(
      parseConsentResolution({
        status: "redirect_mismatch",
        requestId: "req_04",
        attemptedRedirect: "evil.example",
      }),
    ).toEqual({ status: "redirect_mismatch", requestId: "req_04", attemptedRedirect: "evil.example" });

    expect(
      parseConsentResolution({
        status: "scope_not_allowed",
        requestId: "req_05",
        disallowedScopes: ["admin:read"],
      }),
    ).toEqual({ status: "scope_not_allowed", requestId: "req_05", disallowedScopes: ["admin:read"] });

    expect(
      parseConsentResolution({
        status: "already_authorized",
        requestId: "req_06",
        applicationName: "United Workspace",
        redirectHost: "workspace.united.example",
      }),
    ).toEqual({
      status: "already_authorized",
      requestId: "req_06",
      applicationName: "United Workspace",
      redirectHost: "workspace.united.example",
    });
  });

  it("rejects statuses outside the frozen union", () => {
    expect(() => parseConsentResolution({ status: "approved", requestId: "req_01" })).toThrow(
      ApiResponseShapeError,
    );
  });

  it("rejects members with missing or wrongly typed fields", () => {
    expect(() => parseConsentResolution({ status: "expired", requestId: 123 })).toThrow(
      ApiResponseShapeError,
    );
    expect(() =>
      parseConsentResolution({
        status: "scope_not_allowed",
        requestId: "req_05",
        disallowedScopes: "admin:read",
      }),
    ).toThrow(ApiResponseShapeError);
    expect(() => parseConsentResolution({ status: "valid" })).toThrow(ApiResponseShapeError);
    expect(() =>
      parseConsentResolution({
        status: "valid",
        request: { requestId: "req_01", applicationName: "App" },
      }),
    ).toThrow(ApiResponseShapeError);
  });

  it("rejects non-object bodies", () => {
    expect(() => parseConsentResolution(null)).toThrow(ApiResponseShapeError);
    expect(() => parseConsentResolution("valid")).toThrow(ApiResponseShapeError);
    expect(() => parseConsentResolution([])).toThrow(ApiResponseShapeError);
  });
});

describe("parseDecisionResponse", () => {
  it("returns the validated redirect URL", () => {
    expect(parseDecisionResponse({ redirectUrl: "https://client.example/cb?code=x" })).toEqual({
      redirectUrl: "https://client.example/cb?code=x",
    });
  });

  it("rejects a missing or empty redirectUrl", () => {
    expect(() => parseDecisionResponse({})).toThrow(ApiResponseShapeError);
    expect(() => parseDecisionResponse({ redirectUrl: "" })).toThrow(ApiResponseShapeError);
    expect(() => parseDecisionResponse(null)).toThrow(ApiResponseShapeError);
  });
});

describe("parseAuthorizedApplications", () => {
  const row = {
    grantId: "grant_001",
    applicationId: "app_001",
    applicationName: "United Workspace",
    applicationOwner: "United",
    clientType: "confidential",
    grantedAt: "2026-08-01T00:00:00Z",
    lastUsedAt: null,
    scopes: ["openid", "profile"],
    hasOfflineAccess: false,
    status: "active",
  };

  it("parses a well-formed row with null lastUsedAt", () => {
    expect(parseAuthorizedApplications([row])).toEqual([row]);
  });

  it("rejects non-array bodies and malformed rows", () => {
    expect(() => parseAuthorizedApplications({ rows: [] })).toThrow(ApiResponseShapeError);
    expect(() => parseAuthorizedApplications([{ ...row, clientType: "native" }])).toThrow(
      ApiResponseShapeError,
    );
    expect(() => parseAuthorizedApplications([{ ...row, status: "disabled" }])).toThrow(
      ApiResponseShapeError,
    );
    expect(() => parseAuthorizedApplications([{ ...row, lastUsedAt: 123 }])).toThrow(
      ApiResponseShapeError,
    );
    expect(() => parseAuthorizedApplications([{ ...row, scopes: "openid" }])).toThrow(
      ApiResponseShapeError,
    );
  });
});

describe("parseCurrentUser", () => {
  it("parses a minimal consumer user", () => {
    expect(
      parseCurrentUser({
        userId: "usr_01",
        displayName: "林知行",
        nickname: null,
        avatarUrl: null,
        email: "zhixing.lin@example.com",
        phoneMasked: "+86 138****0000",
        personas: ["consumer"],
        employeeProfile: null,
      }),
    ).toEqual({
      userId: "usr_01",
      displayName: "林知行",
      email: "zhixing.lin@example.com",
      phoneMasked: "+86 138****0000",
      personas: ["consumer"],
    });
  });

  it("parses an employee user with optional fields", () => {
    expect(
      parseCurrentUser({
        userId: "usr_02",
        displayName: "周予安",
        nickname: "予安",
        avatarUrl: "/media/avatar.png",
        email: "yuan.zhou@example.com",
        phoneMasked: "+86 139****0000",
        personas: ["consumer", "employee"],
        employeeProfile: { employeeId: "emp_01", departmentName: "平台组", title: "工程师" },
      }),
    ).toEqual({
      userId: "usr_02",
      displayName: "周予安",
      nickname: "予安",
      avatarUrl: "/media/avatar.png",
      email: "yuan.zhou@example.com",
      phoneMasked: "+86 139****0000",
      personas: ["consumer", "employee"],
      employeeProfile: { employeeId: "emp_01", departmentName: "平台组", title: "工程师" },
    });
  });

  it("rejects unknown personas and malformed profiles", () => {
    expect(() =>
      parseCurrentUser({
        userId: "usr_03",
        displayName: "X",
        email: "x@example.com",
        phoneMasked: "",
        personas: ["admin"],
      }),
    ).toThrow(ApiResponseShapeError);
    expect(() =>
      parseCurrentUser({
        userId: "usr_04",
        displayName: "X",
        email: "x@example.com",
        phoneMasked: "",
        personas: [],
        employeeProfile: { employeeId: "emp_01" },
      }),
    ).toThrow(ApiResponseShapeError);
    expect(() => parseCurrentUser({ displayName: "X" })).toThrow(ApiResponseShapeError);
  });
});

describe("parseMfaRequiredResponse", () => {
  it("narrows the 202 login body onto the frozen challenge shape", () => {
    expect(
      parseMfaRequiredResponse({
        status: "mfa_required",
        mfaToken: "opaque-token",
        availableMethods: ["totp", "recovery_code"],
        expiresAt: "2026-08-07T12:05:30Z",
      }),
    ).toEqual({ mfaToken: "opaque-token", availableMethods: ["totp", "recovery_code"] });
  });

  it("rejects unknown verification methods", () => {
    expect(() =>
      parseMfaRequiredResponse({
        status: "mfa_required",
        mfaToken: "t",
        availableMethods: ["sms"],
      }),
    ).toThrow(ApiResponseShapeError);
  });

  it("rejects wrong status, missing token and empty method lists", () => {
    expect(() =>
      parseMfaRequiredResponse({ status: "ok", mfaToken: "t", availableMethods: ["totp"] }),
    ).toThrow(ApiResponseShapeError);
    expect(() =>
      parseMfaRequiredResponse({ status: "mfa_required", availableMethods: ["totp"] }),
    ).toThrow(ApiResponseShapeError);
    expect(() =>
      parseMfaRequiredResponse({ status: "mfa_required", mfaToken: "t", availableMethods: [] }),
    ).toThrow(ApiResponseShapeError);
    expect(() => parseMfaRequiredResponse(null)).toThrow(ApiResponseShapeError);
  });
});

describe("P4.5 account security validators", () => {
  const summary = {
    password: { set: true },
    totp: { enabled: false },
    passkeys: [
      { passkeyId: "pk-active", createdAt: null, state: "active" },
      { passkeyId: "pk-pending", createdAt: "2026-08-09T10:00:00Z", state: "pending" },
    ],
    recoveryCodes: { available: false, deferredReason: "provider_unsupported" },
  };

  it("preserves multiple passkeys, pending state and nullable creation time", () => {
    expect(parseSecuritySummary(summary)).toEqual(summary);
  });

  it("fails closed on unknown passkey state or real recovery-code availability", () => {
    expect(() => parseSecuritySummary({ ...summary, passkeys: [{ ...summary.passkeys[0], state: "ready" }] })).toThrow(
      ApiResponseShapeError,
    );
    expect(() => parseSecuritySummary({
      ...summary,
      recoveryCodes: { available: true, deferredReason: "provider_unsupported" },
    })).toThrow(ApiResponseShapeError);
  });

  it("narrows granted and MFA-required reauthentication outcomes", () => {
    expect(parseReauthenticationOutcome({
      status: "granted",
      reauthToken: "grant",
      expiresAt: "2026-08-09T10:00:00Z",
    })).toEqual({ status: "granted", reauthToken: "grant", expiresAt: "2026-08-09T10:00:00Z" });

    expect(parseReauthenticationOutcome({
      status: "mfa_required",
      reauthToken: "challenge",
      availableMethods: ["totp", "passkey"],
      passkeyRequestOptions: { challenge: "Y2hhbGxlbmdl" },
      expiresAt: "2026-08-09T10:00:00Z",
    })).toEqual({
      status: "mfa_required",
      reauthToken: "challenge",
      availableMethods: ["totp", "passkey"],
      passkeyRequestOptions: { challenge: "Y2hhbGxlbmdl" },
      expiresAt: "2026-08-09T10:00:00Z",
    });
  });

  it("rejects unknown MFA methods and passkey challenges without request options", () => {
    expect(() => parseReauthenticationOutcome({
      status: "mfa_required",
      reauthToken: "challenge",
      availableMethods: ["sms"],
      expiresAt: "x",
    })).toThrow(ApiResponseShapeError);
    expect(() => parseReauthenticationOutcome({
      status: "mfa_required",
      reauthToken: "challenge",
      availableMethods: ["passkey"],
      expiresAt: "x",
    })).toThrow(ApiResponseShapeError);
  });

  it("keeps the enrollment capability available while narrowing options", () => {
    expect(parsePasskeyEnrollment({
      enrollmentToken: "enrollment",
      passkeyId: "pk-new",
      publicKeyCredentialCreationOptions: { challenge: "Y2hhbGxlbmdl" },
    })).toEqual({
      enrollmentToken: "enrollment",
      passkeyId: "pk-new",
      publicKeyCredentialCreationOptions: { challenge: "Y2hhbGxlbmdl" },
    });
    expect(() => parsePasskeyEnrollment({
      enrollmentToken: "enrollment",
      passkeyId: "pk-new",
      publicKeyCredentialCreationOptions: "escaped-json",
    })).toThrow(ApiResponseShapeError);
  });

  it("rejects a confirmation whose provider passkey ID changed", () => {
    expect(parsePasskeyEnrollmentConfirmation(
      { status: "confirmed", passkeyId: "pk-new" },
      "pk-new",
    )).toEqual({ status: "confirmed", passkeyId: "pk-new" });
    expect(() => parsePasskeyEnrollmentConfirmation(
      { status: "confirmed", passkeyId: "pk-other" },
      "pk-new",
    )).toThrow(ApiResponseShapeError);
  });
});
