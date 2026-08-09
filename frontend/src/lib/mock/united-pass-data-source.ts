//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Mock data source implementation backing the frozen frontend
//

import type { UnitedPassDataSource } from "@/lib/api/united-pass-data-source";
import { SYSTEM_NAME } from "@/lib/branding";
import type { AuthorizedApplication } from "@/features/account/types";
import type { CursorPage, PageQuery } from "@/types/pagination";
import { FULL_PERMISSIONS } from "@/types/permissions";
import type {
  AllowedScope,
  ApplicationStatus,
  ApplicationUpdateInput,
  ApplicationWithInitialClientInput,
  ApplicationWithInitialClientResult,
  OAuthApplication,
  OAuthApplicationDetail,
  OAuthClient,
  OAuthClientCreateInput,
  OAuthClientCreationResult,
  SecretRotationResult,
} from "@/features/applications/types";
import { getClientProfileConfig } from "@/features/applications/types";
import type { ConsentDecision, ConsentResolution, ConsentRequest } from "@/features/authorization/types";
import type {
  AuditExportResult,
  AuditQuery,
  DepartmentDetail,
  DirectorySyncHistoryEntry,
  DirectorySyncResult,
  EmployeeDetail,
  EmployeeLinkInput,
  ProviderDetail,
  SyncConflict,
  UserDetail,
} from "@/features/admin/types";
import type {
  PolicyDetail,
  PolicyDraftInput,
  PolicySimulationInput,
  PolicySimulationResult,
} from "@/features/policies/types";
import {
  validateApplicationCreateInput,
  validateOAuthClientCreateInput,
  validateConsentModeWithAudience,
} from "@/features/applications/validation";

const externalAppUser = {
  userId: "usr_06APPUSER7N2X4Q8K5M9",
  displayName: "陆晴",
  nickname: "小陆",
  email: "app.user@example.com",
  phoneMasked: "+86 139 **** 2048",
  personas: ["consumer"],
} satisfies Awaited<ReturnType<UnitedPassDataSource["getCurrentUser"]>>;

const employeeAdminUser = {
  userId: "usr_01JUP8M8B4Q7R4T6PK1D",
  displayName: "林知行",
  nickname: "知行",
  email: "zhixing.lin@example.com",
  phoneMasked: "+86 138 **** 5621",
  personas: ["consumer", "employee"],
  employeeProfile: {
    employeeId: "UP-1042",
    departmentName: "产品与体验 / 身份平台",
    title: "产品设计师",
  },
} satisfies Awaited<ReturnType<UnitedPassDataSource["getCurrentUser"]>>;

const securitySummary = {
  password: { set: true },
  totp: { enabled: true },
  passkeys: [],
  recoveryCodes: { available: false, deferredReason: "provider_unsupported" },
} satisfies Awaited<ReturnType<UnitedPassDataSource["getSecuritySummary"]>>;

const sessions = [
  { sessionId: "ses_current", deviceName: "MacBook Pro", clientName: "Chrome 138 · macOS", approximateLocation: "上海市", ipAddressMasked: "203.0.113.*", lastActiveAt: "2026-08-04T05:42:00Z", isCurrent: true },
  { sessionId: "ses_mobile", deviceName: "iPhone 17", clientName: `${SYSTEM_NAME} · iOS`, approximateLocation: "上海市", ipAddressMasked: "198.51.100.*", lastActiveAt: "2026-08-03T13:16:00Z", isCurrent: false },
  { sessionId: "ses_edge", deviceName: "Windows 设备", clientName: "Edge 138 · Windows", approximateLocation: "杭州市", ipAddressMasked: "192.0.2.*", lastActiveAt: "2026-07-29T01:05:00Z", isCurrent: false },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getSessions"]>>;

const consentRequest = {
  requestId: "consent_demo_001",
  applicationName: "United Workspace",
  applicationDescription: "团队协作与项目管理工作台",
  applicationOwner: "协作产品团队",
  redirectHost: "workspace.united.example",
  scopes: [
    { scope: "openid", label: "确认你的身份", description: "获取稳定的用户标识，用于完成登录。" },
    { scope: "profile", label: "查看基本资料", description: "查看姓名、头像和账户类型。" },
    { scope: "email", label: "查看邮箱地址", description: "读取当前账户绑定的邮箱地址。" },
  ],
} satisfies ConsentRequest;

const consentResolutions: Record<string, ConsentResolution> = {
  consent_demo_001: { status: "valid", request: consentRequest },
  consent_demo_002: { status: "expired", requestId: "consent_demo_002", expiredAt: "2026-08-04T12:00:00Z" },
  consent_demo_003: { status: "client_not_found", requestId: "consent_demo_003" },
  consent_demo_004: { status: "redirect_mismatch", requestId: "consent_demo_004", attemptedRedirect: "https://evil.example/callback" },
  consent_demo_005: { status: "unauthenticated", requestId: "consent_demo_005" },
  consent_demo_006: { status: "scope_not_allowed", requestId: "consent_demo_006", disallowedScopes: ["admin:read", "admin:write"] },
  consent_demo_007: { status: "already_authorized", requestId: "consent_demo_007", applicationName: "United Mobile", redirectHost: "mobile.united.example" },
};

const initialAuthorizedApplications: AuthorizedApplication[] = [
  {
    grantId: "grant_001",
    applicationId: "app_workspace",
    applicationName: "United Workspace",
    applicationOwner: "协作产品团队",
    clientType: "confidential",
    grantedAt: "2026-07-15T08:30:00Z",
    lastUsedAt: "2026-08-04T05:42:00Z",
    scopes: ["openid", "profile", "email"],
    hasOfflineAccess: false,
    status: "active",
  },
  {
    grantId: "grant_002",
    applicationId: "app_mobile",
    applicationName: "United Mobile",
    applicationOwner: "移动端团队",
    clientType: "public",
    grantedAt: "2026-06-20T10:15:00Z",
    lastUsedAt: "2026-08-03T13:16:00Z",
    scopes: ["openid", "profile", "offline_access"],
    hasOfflineAccess: true,
    status: "active",
  },
  {
    grantId: "grant_003",
    applicationId: "app_legacy",
    applicationName: "Legacy Reports",
    applicationOwner: "数据团队",
    clientType: "confidential",
    grantedAt: "2026-05-10T14:00:00Z",
    lastUsedAt: "2026-06-16T12:00:00Z",
    scopes: ["openid", "profile", "email", "reporting:read"],
    hasOfflineAccess: false,
    status: "revoked",
  },
];

const availableScopes: AllowedScope[] = [
  { scope: "openid", label: "OpenID", description: "获取稳定用户标识，完成 OIDC 登录。", required: true },
  { scope: "profile", label: "基本资料", description: "查看姓名、头像和账户类型。", required: false },
  { scope: "email", label: "邮箱地址", description: "读取当前账户绑定的邮箱地址。", required: false },
  { scope: "phone", label: "手机号", description: "读取脱敏后的手机号。", required: false },
  { scope: "offline_access", label: "离线访问", description: "在用户不活跃时通过 Refresh Token 继续访问已授权数据。", required: false },
  { scope: "reporting:read", label: "报表读取", description: "读取应用关联的业务报表。", required: false },
];

const users = [
  { userId: externalAppUser.userId, displayName: externalAppUser.displayName, email: externalAppUser.email, personaLabel: "外部用户", status: "active", lastActiveAt: "2026-08-04T05:48:00Z" },
  { userId: employeeAdminUser.userId, displayName: employeeAdminUser.displayName, email: employeeAdminUser.email, personaLabel: "外部用户 · 员工", status: "active", lastActiveAt: "2026-08-04T05:42:00Z" },
  { userId: "usr_02F4PXKQ0EZP5F7B9V3C", displayName: "周予安", email: "yuan.zhou@example.com", personaLabel: "员工", status: "active", lastActiveAt: "2026-08-04T04:18:00Z" },
  { userId: "usr_03D1KMM3AGX8G2QW5T9N", displayName: "陈默", email: "mo.chen@example.net", personaLabel: "外部用户", status: "pending", lastActiveAt: "2026-08-02T11:03:00Z" },
  { userId: "usr_04ABT7S6HHQ1N8K2YM0E", displayName: "苏晚", email: "wan.su@example.org", personaLabel: "外部用户", status: "disabled", lastActiveAt: "2026-07-21T08:44:00Z" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getUsers"]>>["items"];

const employees = [
  { userId: employeeAdminUser.userId, displayName: "林知行", employeeId: "UP-1042", departmentName: "身份平台", title: "产品设计师", status: "active" },
  { userId: "usr_02F4PXKQ0EZP5F7B9V3C", displayName: "周予安", employeeId: "UP-0928", departmentName: "基础架构", title: "高级工程师", status: "active" },
  { userId: "usr_05QG6E8W4NR7Y2Z1PC9S", displayName: "顾言", employeeId: "UP-0815", departmentName: "客户成功", title: "客户成功经理", status: "offboarding" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getEmployees"]>>["items"];

const departments = [
  { departmentId: "dep_identity", name: "身份平台", parentName: "产品与体验", memberCount: 18, ownerName: "许清和" },
  { departmentId: "dep_infra", name: "基础架构", parentName: "技术中心", memberCount: 32, ownerName: "程越" },
  { departmentId: "dep_success", name: "客户成功", parentName: "商业化中心", memberCount: 24, ownerName: "沈叙" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getDepartments"]>>;

const userDetails: Record<string, UserDetail> = {
  usr_01JUP8M8B4Q7R4T6PK1D: {
    userId: "usr_01JUP8M8B4Q7R4T6PK1D",
    displayName: "林知行",
    email: "zhixing.lin@example.com",
    phoneMasked: "+86 138 **** 5621",
    personaLabel: "外部用户 · 员工",
    status: "active",
    lastActiveAt: "2026-08-04T05:42:00Z",
    personas: ["consumer", "employee"],
    employeeProfile: {
      employeeId: "UP-1042",
      departmentName: "身份平台",
      title: "产品设计师",
    },
    linkedIdentities: [],
    activeSessions: [
      { sessionId: "ses_current", deviceName: "MacBook Pro", lastActiveAt: "2026-08-04T05:42:00Z", isCurrent: true },
    ],
    authorizedApplications: [
      { applicationName: "United Workspace", scopes: ["openid", "profile", "email"], grantedAt: "2026-07-15T08:30:00Z", status: "active" },
    ],
    recentAuditEvents: [
      { eventId: "evt_001", eventType: "用户登录", actorName: "林知行", actorId: "usr_01JUP8M8B4Q7R4T6PK1D", targetLabel: SYSTEM_NAME, targetId: "system_united_pass", occurredAt: "2026-08-04T05:42:00Z", result: "success" as const, requestId: "req_login_001", details: "通过密码 + TOTP 完成登录。客户端：Chrome 138 · macOS。" },
    ],
  },
  usr_06APPUSER7N2X4Q8K5M9: {
    userId: "usr_06APPUSER7N2X4Q8K5M9",
    displayName: "陆晴",
    email: "app.user@example.com",
    phoneMasked: "+86 139 **** 2048",
    personaLabel: "外部用户",
    status: "active",
    lastActiveAt: "2026-08-04T05:48:00Z",
    personas: ["consumer"],
    linkedIdentities: [],
    activeSessions: [],
    authorizedApplications: [
      { applicationName: "United Workspace", scopes: ["openid", "profile", "email"], grantedAt: "2026-07-15T08:30:00Z", status: "active" },
      { applicationName: "United Mobile", scopes: ["openid", "profile", "offline_access"], grantedAt: "2026-06-20T10:15:00Z", status: "active" },
    ],
    recentAuditEvents: [],
  },
};

const employeeDetails: Record<string, EmployeeDetail> = {
  usr_01JUP8M8B4Q7R4T6PK1D: {
    userId: "usr_01JUP8M8B4Q7R4T6PK1D",
    displayName: "林知行",
    email: "zhixing.lin@example.com",
    employeeId: "UP-1042",
    departmentName: "身份平台",
    departmentId: "dep_identity",
    title: "产品设计师",
    status: "active",
    supervisorName: "许清和",
    onboardedAt: "2025-03-15T00:00:00Z",
    linkedConsumerAccount: true,
  },
  usr_02F4PXKQ0EZP5F7B9V3C: {
    userId: "usr_02F4PXKQ0EZP5F7B9V3C",
    displayName: "周予安",
    email: "yuan.zhou@example.com",
    employeeId: "UP-0928",
    departmentName: "基础架构",
    departmentId: "dep_infra",
    title: "高级工程师",
    status: "active",
    supervisorName: "程越",
    onboardedAt: "2024-08-01T00:00:00Z",
    linkedConsumerAccount: true,
  },
  usr_05QG6E8W4NR7Y2Z1PC9S: {
    userId: "usr_05QG6E8W4NR7Y2Z1PC9S",
    displayName: "顾言",
    email: "yan.gu@example.com",
    employeeId: "UP-0815",
    departmentName: "客户成功",
    departmentId: "dep_success",
    title: "客户成功经理",
    status: "offboarding",
    supervisorName: "沈叙",
    onboardedAt: "2024-06-10T00:00:00Z",
    linkedConsumerAccount: true,
  },
};

const departmentDetails: Record<string, DepartmentDetail> = {
  dep_identity: {
    departmentId: "dep_identity",
    name: "身份平台",
    parentDepartmentId: "dep_product",
    parentName: "产品与体验",
    ownerName: "许清和",
    memberCount: 18,
    childDepartments: [],
    members: [
      { userId: "usr_01JUP8M8B4Q7R4T6PK1D", displayName: "林知行", title: "产品设计师", employeeId: "UP-1042" },
      { userId: "usr_0A1", displayName: "许清和", title: "部门负责人", employeeId: "UP-0901" },
      { userId: "usr_0A2", displayName: "陈思远", title: "前端工程师", employeeId: "UP-1102" },
    ],
  },
  dep_infra: {
    departmentId: "dep_infra",
    name: "基础架构",
    parentDepartmentId: "dep_tech",
    parentName: "技术中心",
    ownerName: "程越",
    memberCount: 32,
    childDepartments: [
      { departmentId: "dep_infra_sre", name: "SRE", memberCount: 8 },
      { departmentId: "dep_infra_data", name: "数据平台", memberCount: 12 },
    ],
    members: [
      { userId: "usr_02F4PXKQ0EZP5F7B9V3C", displayName: "周予安", title: "高级工程师", employeeId: "UP-0928" },
    ],
  },
  dep_success: {
    departmentId: "dep_success",
    name: "客户成功",
    parentDepartmentId: "dep_commerce",
    parentName: "商业化中心",
    ownerName: "沈叙",
    memberCount: 24,
    childDepartments: [],
    members: [
      { userId: "usr_05QG6E8W4NR7Y2Z1PC9S", displayName: "顾言", title: "客户成功经理", employeeId: "UP-0815" },
    ],
  },
};

const identityProviders = [
  {
    providerId: "provider_feishu",
    displayName: "飞书",
    vendor: "feishu",
    integrationLabel: "飞书开放平台（待技术评审）",
    status: "planned",
    loginEnabled: false,
    linkedUserCount: 0,
    updatedAt: "2026-08-05T06:20:00Z",
  },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getIdentityProviders"]>>["items"];

const providerDetails: Record<string, ProviderDetail> = {
  provider_feishu: {
    providerId: "provider_feishu",
    displayName: "飞书",
    vendor: "feishu",
    status: "planned",
    loginEnabled: false,
    appId: "cli_example_feishu_app",
    secretConfigured: false,
    callbackUrl: "https://pass.example.com/oauth2/feishu/callback",
    contactScope: "contact:user.base:readonly,contact:department.base:readonly",
    linkedUserCount: 0,
    lastSyncAt: null,
    lastSyncResult: null,
    updatedAt: "2026-08-05T06:20:00Z",
  },
};

const syncHistory: DirectorySyncHistoryEntry[] = [
  {
    syncId: "sync_001",
    providerId: "provider_feishu",
    startedAt: "2026-08-04T02:00:00Z",
    completedAt: "2026-08-04T02:03:12Z",
    status: "partial",
    summary: "新增 12 个部门，更新 3 个部门，新增 45 名员工，检测到 2 个关联冲突",
  },
];

const syncConflicts: SyncConflict[] = [
  {
    conflictId: "conflict_001",
    providerId: "provider_feishu",
    externalSubject: "feishu_user_001",
    externalName: "陈默",
    externalEmail: "chen.mo@example.com",
    matchedUserId: "usr_01JUP8M8B4Q7R4T6PK1D",
    matchedUserName: "林知行",
    matchReason: "email",
    status: "pending",
    detectedAt: "2026-08-04T02:01:30Z",
  },
  {
    conflictId: "conflict_002",
    providerId: "provider_feishu",
    externalSubject: "feishu_user_002",
    externalName: "程越",
    externalEmail: "cheng.yue@example.com",
    matchedUserId: null,
    matchedUserName: null,
    matchReason: "name",
    status: "pending",
    detectedAt: "2026-08-04T02:02:15Z",
  },
];

const initialApplications = [
  { applicationId: "app_workspace", name: "United Workspace", audience: "external", ownerId: "owner_workspace", ownerName: "协作产品团队", status: "active", clientCount: 1, updatedAt: "2026-08-01T06:10:00Z" },
  { applicationId: "app_mobile", name: "United Mobile", audience: "external", ownerId: "owner_mobile", ownerName: "移动端团队", status: "active", clientCount: 1, updatedAt: "2026-07-28T02:32:00Z" },
  { applicationId: "app_legacy", name: "Legacy Reports", audience: "internal", ownerId: "owner_legacy", ownerName: "数据团队", status: "disabled", clientCount: 1, updatedAt: "2026-06-16T12:00:00Z" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getApplications"]>>["items"];

const initialApplicationDetails: Record<string, OAuthApplicationDetail> = {
  app_workspace: {
    applicationId: "app_workspace",
    name: "United Workspace",
    description: "团队协作与项目管理工作台，支持任务、文档和日程整合。",
    logoUrl: null,
    audience: "external",
    ownerId: "owner_workspace",
    ownerName: "协作产品团队",
    status: "active",
    clients: [
      {
        clientId: "ws_9f3a8b2c1e7d4600",
        applicationId: "app_workspace",
        name: "Workspace Web 客户端",
        clientType: "confidential",
        grantTypes: ["authorization_code", "refresh_token"],
        tokenEndpointAuthMethod: "client_secret_post",
        redirectUris: [
          { uri: "https://workspace.united.example/auth/callback", isLoopback: false, addedAt: "2026-07-01T03:00:00Z" },
          { uri: "https://staging.workspace.united.example/auth/callback", isLoopback: false, addedAt: "2026-07-15T06:20:00Z" },
          { uri: "http://localhost:3000/callback", isLoopback: true, addedAt: "2026-07-20T08:00:00Z" },
        ],
        logoutUri: "https://workspace.united.example/auth/logout",
        allowedScopes: [
          { scope: "openid", label: "OpenID", description: "获取稳定用户标识，完成 OIDC 登录。", required: true },
          { scope: "profile", label: "基本资料", description: "查看姓名、头像和账户类型。", required: false },
          { scope: "email", label: "邮箱地址", description: "读取当前账户绑定的邮箱地址。", required: false },
        ],
        consentMode: "always",
        status: "active",
        clientSecrets: [
          { secretId: "sec_ws_001", label: "生产环境密钥", createdAt: "2026-07-01T03:00:00Z", lastRotatedAt: "2026-07-15T06:20:00Z" },
        ],
        createdAt: "2026-07-01T03:00:00Z",
        updatedAt: "2026-08-01T06:10:00Z",
      },
    ],
    grants: [
      { grantId: "grant_001", userLabel: "陆晴", scopes: ["openid", "profile", "email"], grantedAt: "2026-07-15T08:30:00Z", lastUsedAt: "2026-08-04T05:42:00Z", status: "active" },
      { grantId: "grant_004", userLabel: "周予安", scopes: ["openid", "profile"], grantedAt: "2026-07-20T11:00:00Z", lastUsedAt: "2026-08-03T09:15:00Z", status: "active" },
    ],
    auditEntries: [
      { eventId: "app_evt_001", eventType: "密钥轮换", actorName: "林知行", occurredAt: "2026-07-15T06:20:00Z", result: "success" },
      { eventId: "app_evt_002", eventType: "Redirect URI 新增", actorName: "林知行", occurredAt: "2026-07-20T08:00:00Z", result: "success" },
    ],
    createdAt: "2026-07-01T03:00:00Z",
    updatedAt: "2026-08-01T06:10:00Z",
  },
  app_mobile: {
    applicationId: "app_mobile",
    name: "United Mobile",
    description: "移动端应用，使用 PKCE 公共客户端。",
    logoUrl: null,
    audience: "external",
    ownerId: "owner_mobile",
    ownerName: "移动端团队",
    status: "active",
    clients: [
      {
        clientId: "mb_2c7f4e8a1b9d0300",
        applicationId: "app_mobile",
        name: "United Mobile 客户端",
        clientType: "public",
        grantTypes: ["authorization_code", "refresh_token"],
        tokenEndpointAuthMethod: "none",
        redirectUris: [
          { uri: "com.united.mobile:/oauth2callback", isLoopback: false, addedAt: "2026-06-20T10:00:00Z" },
          { uri: "http://localhost:8081/callback", isLoopback: true, addedAt: "2026-06-25T14:00:00Z" },
        ],
        logoutUri: null,
        allowedScopes: [
          { scope: "openid", label: "OpenID", description: "获取稳定用户标识，完成 OIDC 登录。", required: true },
          { scope: "profile", label: "基本资料", description: "查看姓名、头像和账户类型。", required: false },
          { scope: "offline_access", label: "离线访问", description: "在用户不活跃时通过 Refresh Token 继续访问已授权数据。", required: false },
        ],
        consentMode: "always",
        status: "active",
        clientSecrets: [],
        createdAt: "2026-06-20T10:00:00Z",
        updatedAt: "2026-07-28T02:32:00Z",
      },
    ],
    grants: [
      { grantId: "grant_002", userLabel: "陆晴", scopes: ["openid", "profile", "offline_access"], grantedAt: "2026-06-20T10:15:00Z", lastUsedAt: "2026-08-03T13:16:00Z", status: "active" },
    ],
    auditEntries: [
      { eventId: "app_evt_003", eventType: "应用创建", actorName: "程越", occurredAt: "2026-06-20T10:00:00Z", result: "success" },
    ],
    createdAt: "2026-06-20T10:00:00Z",
    updatedAt: "2026-07-28T02:32:00Z",
  },
  app_legacy: {
    applicationId: "app_legacy",
    name: "Legacy Reports",
    description: "已停用的旧版报表应用。",
    logoUrl: null,
    audience: "internal",
    ownerId: "owner_legacy",
    ownerName: "数据团队",
    status: "disabled",
    clients: [
      {
        clientId: "lr_8a1b3c5d7e9f2000",
        applicationId: "app_legacy",
        name: "Legacy Reports 客户端",
        clientType: "confidential",
        grantTypes: ["authorization_code", "refresh_token"],
        tokenEndpointAuthMethod: "client_secret_post",
        redirectUris: [
          { uri: "https://reports.united.example/auth/callback", isLoopback: false, addedAt: "2026-05-01T08:00:00Z" },
        ],
        logoutUri: "https://reports.united.example/auth/logout",
        allowedScopes: [
          { scope: "openid", label: "OpenID", description: "获取稳定用户标识，完成 OIDC 登录。", required: true },
          { scope: "profile", label: "基本资料", description: "查看姓名、头像和账户类型。", required: false },
          { scope: "email", label: "邮箱地址", description: "读取当前账户绑定的邮箱地址。", required: false },
          { scope: "reporting:read", label: "报表读取", description: "读取应用关联的业务报表。", required: false },
        ],
        consentMode: "first_authorization",
        status: "disabled",
        clientSecrets: [
          { secretId: "sec_lr_001", label: "原始密钥", createdAt: "2026-05-01T08:00:00Z", lastRotatedAt: null },
        ],
        createdAt: "2026-05-01T08:00:00Z",
        updatedAt: "2026-06-16T12:00:00Z",
      },
    ],
    grants: [
      { grantId: "grant_003", userLabel: "陆晴", scopes: ["openid", "profile", "email", "reporting:read"], grantedAt: "2026-05-10T14:00:00Z", lastUsedAt: "2026-06-16T12:00:00Z", status: "revoked" },
    ],
    auditEntries: [
      { eventId: "app_evt_004", eventType: "应用停用", actorName: "周予安", occurredAt: "2026-06-16T12:00:00Z", result: "success" },
    ],
    createdAt: "2026-05-01T08:00:00Z",
    updatedAt: "2026-06-16T12:00:00Z",
  },
};

const policies = [
  { policyId: "pol_application_manage", name: "应用管理员维护 OAuth 应用", resource: "application:*", version: 7, status: "published", updatedBy: "周予安", updatedAt: "2026-08-03T07:45:00Z" },
  { policyId: "pol_employee_read", name: "部门负责人查看直属员工", resource: "employee:*", version: 3, status: "published", updatedBy: "林知行", updatedAt: "2026-07-30T03:20:00Z" },
  { policyId: "pol_audit_export", name: "安全审计导出限制", resource: "audit:export", version: 1, status: "draft", updatedBy: "程越", updatedAt: "2026-08-04T01:14:00Z" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getPolicies"]>>["items"];

const policyDetails: Record<string, PolicyDetail> = {
  pol_application_manage: {
    policyId: "pol_application_manage",
    name: "应用管理员维护 OAuth 应用",
    description: "允许应用管理员创建、编辑、停用和删除 OAuth 应用及其 Client。",
    resource: "application:*",
    action: "application.manage",
    effect: "allow",
    version: 7,
    status: "published",
    principals: [
      { attribute: "role", operator: "eq", value: "application_admin" },
    ],
    conditions: [
      { attribute: "department", operator: "in", value: "identity_platform,security" },
    ],
    updatedBy: "周予安",
    updatedAt: "2026-08-03T07:45:00Z",
    versionHistory: [
      { version: 7, status: "published", updatedBy: "周予安", updatedAt: "2026-08-03T07:45:00Z", changeSummary: "增加 security 部门到条件范围" },
      { version: 6, status: "published", updatedBy: "周予安", updatedAt: "2026-07-28T03:12:00Z", changeSummary: "收紧 principal 属性" },
      { version: 5, status: "published", updatedBy: "林知行", updatedAt: "2026-07-15T08:30:00Z", changeSummary: "初始发布版本" },
    ],
  },
  pol_employee_read: {
    policyId: "pol_employee_read",
    name: "部门负责人查看直属员工",
    description: "允许部门负责人查看本部门成员的资料和状态。",
    resource: "employee:*",
    action: "employee.read",
    effect: "allow",
    version: 3,
    status: "published",
    principals: [
      { attribute: "role", operator: "eq", value: "department_owner" },
    ],
    conditions: [
      { attribute: "target_department", operator: "eq", value: "${principal.department}" },
    ],
    updatedBy: "林知行",
    updatedAt: "2026-07-30T03:20:00Z",
    versionHistory: [
      { version: 3, status: "published", updatedBy: "林知行", updatedAt: "2026-07-30T03:20:00Z", changeSummary: "修正部门匹配条件" },
      { version: 2, status: "published", updatedBy: "周予安", updatedAt: "2026-07-20T06:00:00Z", changeSummary: "调整 principal 定义" },
      { version: 1, status: "published", updatedBy: "周予安", updatedAt: "2026-07-10T02:00:00Z", changeSummary: "初始版本" },
    ],
  },
  pol_audit_export: {
    policyId: "pol_audit_export",
    name: "安全审计导出限制",
    description: "仅允许安全团队成员导出审计日志，且不允许导出包含 Token 的字段。",
    resource: "audit:export",
    action: "audit.export",
    effect: "allow",
    version: 1,
    status: "draft",
    principals: [
      { attribute: "role", operator: "in", value: "security_admin,compliance_auditor" },
    ],
    conditions: [
      { attribute: "export_scope", operator: "neq", value: "token_fields" },
    ],
    updatedBy: "程越",
    updatedAt: "2026-08-04T01:14:00Z",
    versionHistory: [
      { version: 1, status: "draft", updatedBy: "程越", updatedAt: "2026-08-04T01:14:00Z", changeSummary: "草稿创建" },
    ],
  },
};

const auditEvents = [
  {
    eventId: "evt_001",
    eventType: "用户登录",
    actorName: "林知行",
    actorId: "usr_01JUP8M8B4Q7R4T6PK1D",
    targetLabel: SYSTEM_NAME,
    targetId: "system_united_pass",
    occurredAt: "2026-08-04T05:42:00Z",
    result: "success" as const,
    requestId: "req_login_001",
    details: "通过密码 + TOTP 完成登录。客户端：Chrome 138 · macOS。",
  },
  {
    eventId: "evt_002",
    eventType: "策略发布",
    actorName: "周予安",
    actorId: "usr_02F4PXKQ0EZP5F7B9V3C",
    targetLabel: "应用管理员维护 OAuth 应用",
    targetId: "pol_app_manage",
    occurredAt: "2026-08-03T07:45:00Z",
    result: "success" as const,
    requestId: "req_publish_001",
    details: "策略 v2 发布。影响范围：application:*。决策效果：allow。",
  },
  {
    eventId: "evt_003",
    eventType: "管理操作拒绝",
    actorName: "陈默",
    actorId: "usr_03D1KMM3AGX8G2QW5T9N",
    targetLabel: "员工目录",
    targetId: "admin_employees",
    occurredAt: "2026-08-03T02:18:00Z",
    result: "denied" as const,
    requestId: "req_deny_001",
    details: "ABAC 策略拒绝。用户缺少 employee.manage 权限。",
  },
  {
    eventId: "evt_004",
    eventType: "会话撤销",
    actorName: "林知行",
    actorId: "usr_01JUP8M8B4Q7R4T6PK1D",
    targetLabel: "Windows 设备",
    targetId: "ses_edge",
    occurredAt: "2026-08-02T10:07:00Z",
    result: "success" as const,
    requestId: "req_revoke_001",
    details: "用户主动撤销非当前会话。设备：Edge 138 · Windows。",
  },
  {
    eventId: "evt_005",
    eventType: "OAuth 授权同意",
    actorName: "陆晴",
    actorId: "usr_06APPUSER7N2X4Q8K5M9",
    targetLabel: "United Workspace",
    targetId: "app_workspace",
    occurredAt: "2026-08-01T14:20:00Z",
    result: "success" as const,
    requestId: "req_consent_001",
    details: "用户授权 openid, profile, email。Client: confidential。",
  },
  {
    eventId: "evt_006",
    eventType: "Client Secret 轮换",
    actorName: "林知行",
    actorId: "usr_01JUP8M8B4Q7R4T6PK1D",
    targetLabel: "United Workspace · Web Client",
    targetId: "cli_workspace_web",
    occurredAt: "2026-07-30T09:15:00Z",
    result: "success" as const,
    requestId: "req_rotate_001",
    details: "管理员轮换 Client Secret。旧 Secret 立即失效。",
  },
  {
    eventId: "evt_007",
    eventType: "应用停用",
    actorName: "周予安",
    actorId: "usr_02F4PXKQ0EZP5F7B9V3C",
    targetLabel: "Legacy Reports",
    targetId: "app_legacy",
    occurredAt: "2026-07-28T16:30:00Z",
    result: "success" as const,
    requestId: "req_disable_001",
    details: "管理员停用应用。所有活跃授权和会话已撤销。",
  },
  {
    eventId: "evt_008",
    eventType: "员工入职",
    actorName: "许清和",
    actorId: "usr_0A1",
    targetLabel: "陈思远",
    targetId: "usr_0A2",
    occurredAt: "2026-07-25T08:00:00Z",
    result: "success" as const,
    requestId: "req_onboard_001",
    details: "为既有外部用户创建员工档案。部门：身份平台。职位：前端工程师。保留 Consumer Persona。",
  },
  {
    eventId: "evt_009",
    eventType: "Provider 同步",
    actorName: "系统",
    actorId: "system",
    targetLabel: "飞书",
    targetId: "provider_feishu",
    occurredAt: "2026-08-04T02:03:12Z",
    result: "success" as const,
    requestId: "req_sync_001",
    details: "目录同步完成。新增 12 部门，45 名员工。检测到 2 个身份关联冲突。",
  },
  {
    eventId: "evt_010",
    eventType: "密码修改",
    actorName: "林知行",
    actorId: "usr_01JUP8M8B4Q7R4T6PK1D",
    targetLabel: "自身账户",
    targetId: "usr_01JUP8M8B4Q7R4T6PK1D",
    occurredAt: "2026-07-20T11:22:00Z",
    result: "success" as const,
    requestId: "req_pwd_001",
    details: "用户修改账户密码。重认证后完成。",
  },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getAuditEvents"]>>["items"];

function resolveScopes(scopeIds: string[]): AllowedScope[] {
  const scopeMap = new Map(availableScopes.map((scope) => [scope.scope, scope]));
  const resolved: AllowedScope[] = [];
  for (const scopeId of scopeIds) {
    const scope = scopeMap.get(scopeId);
    if (!scope) {
      throw new Error(`未知的 Scope: ${scopeId}`);
    }
    resolved.push(scope);
  }
  return resolved;
}

function buildRedirectUris(uris: string[], now: string) {
  return uris.map((uri) => ({
    uri,
    isLoopback: uri.startsWith("http://localhost") || uri.startsWith("http://127.0.0.1"),
    addedAt: now,
  }));
}

/**
 * Wraps an array into a CursorPage for mock list queries.
 * The mock returns all items in a single page; the real backend will
 * return actual cursor-paginated results.
 */
function toCursorPage<T>(items: T[], query?: PageQuery): CursorPage<T> {
  let filtered = items;
  if (query?.query) {
    const q = query.query.trim().toLocaleLowerCase("zh-CN");
    if (q) {
      filtered = items.filter((item) =>
        JSON.stringify(item).toLocaleLowerCase("zh-CN").includes(q),
      );
    }
  }
  if (query?.status) {
    filtered = filtered.filter(
      (item) =>
        typeof item === "object" &&
        item !== null &&
        "status" in item &&
        String((item as Record<string, unknown>).status) === query.status,
    );
  }
  return {
    items: filtered,
    page: { nextCursor: null, hasMore: false },
  };
}

/**
 * Filters audit events by AuditQuery fields.
 * Supports eventType, result, actorName, requestId, and date range.
 */
function filterAuditEvents(items: typeof auditEvents, query?: AuditQuery): CursorPage<typeof auditEvents[number]> {
  let filtered = [...items];
  if (query?.query) {
    const q = query.query.trim().toLocaleLowerCase("zh-CN");
    if (q) {
      filtered = filtered.filter((item) =>
        JSON.stringify(item).toLocaleLowerCase("zh-CN").includes(q),
      );
    }
  }
  if (query?.eventType) {
    filtered = filtered.filter((item) => item.eventType === query.eventType);
  }
  if (query?.result) {
    filtered = filtered.filter((item) => item.result === query.result);
  }
  if (query?.actorName) {
    const actor = query.actorName.trim().toLocaleLowerCase("zh-CN");
    filtered = filtered.filter((item) =>
      item.actorName.toLocaleLowerCase("zh-CN").includes(actor),
    );
  }
  if (query?.requestId) {
    filtered = filtered.filter((item) => item.requestId === query.requestId);
  }
  if (query?.from) {
    filtered = filtered.filter((item) => item.occurredAt >= query.from!);
  }
  if (query?.to) {
    filtered = filtered.filter((item) => item.occurredAt <= query.to!);
  }
  return {
    items: filtered,
    page: { nextCursor: null, hasMore: false },
  };
}

/**
 * Resolves the display name for an owner user ID, mirroring the backend
 * contract where ownerId is the stable identifier and ownerName is derived.
 * Unknown IDs fall back to the raw ID so mutations never silently drop data.
 */
function resolveOwnerName(ownerId: string): string {
  const user = users.find((item) => item.userId === ownerId);
  if (user) {
    return user.displayName;
  }
  const employee = employees.find((item) => item.userId === ownerId);
  return employee ? employee.displayName : ownerId;
}

export function createMockUnitedPassDataSource(): UnitedPassDataSource {
  const applications: OAuthApplication[] = structuredClone(initialApplications);
  const applicationDetails: Record<string, OAuthApplicationDetail> = structuredClone(initialApplicationDetails);
  const authorizedApplications: AuthorizedApplication[] = structuredClone(initialAuthorizedApplications);

  return {
    getCurrentUser: () => Promise.resolve(employeeAdminUser),
    getCurrentPermissions: () => Promise.resolve(FULL_PERMISSIONS),
    getSecuritySummary: () => Promise.resolve(securitySummary),
    getSessions: () => Promise.resolve(sessions),
    getConsentResolution: (requestId: string) => {
      const resolution = consentResolutions[requestId];
      if (resolution) {
        return Promise.resolve(resolution);
      }
      return Promise.resolve({ status: "client_not_found", requestId });
    },
    getAuthorizedApplications: () => Promise.resolve(authorizedApplications),
    getAdminDashboard: () => Promise.resolve({
      metrics: [
        { label: "活跃用户", value: "12,840", change: "近 30 天 +8.4%", tone: "positive" },
        { label: "员工账户", value: "486", change: "3 个待完成入职", tone: "attention" },
        { label: "OAuth 应用", value: "24", change: "22 个正常运行", tone: "neutral" },
        { label: "高风险事件", value: "2", change: "需要安全团队复核", tone: "attention" },
      ],
      recentEvents: auditEvents.slice(0, 3),
    }),
    getUsers: (query?: PageQuery) => Promise.resolve(toCursorPage(users, query)),
    getUserDetail: (userId: string) => Promise.resolve(userDetails[userId] ?? null),
    getEmployees: (query?: PageQuery) => Promise.resolve(toCursorPage(employees, query)),
    getEmployeeDetail: (userId: string) => Promise.resolve(employeeDetails[userId] ?? null),
    getDepartments: () => Promise.resolve(departments),
    getDepartmentDetail: (departmentId: string) => Promise.resolve(departmentDetails[departmentId] ?? null),
    getIdentityProviders: (query?: PageQuery) => Promise.resolve(toCursorPage(identityProviders, query)),
    getProviderDetail: (providerId: string): Promise<ProviderDetail | null> => {
      const detail = providerDetails[providerId];
      if (!detail) return Promise.resolve(null);
      return Promise.resolve({ ...detail });
    },
    getDirectorySyncHistory: (providerId?: string): Promise<DirectorySyncHistoryEntry[]> => {
      const filtered = providerId ? syncHistory.filter((e) => e.providerId === providerId) : syncHistory;
      return Promise.resolve([...filtered]);
    },
    getSyncConflicts: (providerId?: string): Promise<SyncConflict[]> => {
      const filtered = providerId ? syncConflicts.filter((c) => c.providerId === providerId) : syncConflicts;
      return Promise.resolve([...filtered]);
    },
    getApplications: (query?: PageQuery) => Promise.resolve(toCursorPage(applications, query)),
    getApplicationDetail: (applicationId: string) => {
      const detail = applicationDetails[applicationId];
      return Promise.resolve(detail ?? null);
    },
    getClientDetail: (applicationId: string, clientId: string) => {
      const detail = applicationDetails[applicationId];
      if (!detail) {
        return Promise.resolve(null);
      }
      const client = detail.clients.find((c) => c.clientId === clientId);
      return Promise.resolve(client ?? null);
    },
    getAvailableScopes: () => Promise.resolve(availableScopes),
    createOAuthClient: (input: OAuthClientCreateInput): Promise<OAuthClientCreationResult> => {
      try {
        validateOAuthClientCreateInput(input);
      } catch (error) {
        return Promise.reject(error);
      }

      const detail = applicationDetails[input.applicationId];
      if (!detail) {
        return Promise.reject(
          new Error(`应用 ${input.applicationId} 不存在，无法创建 OAuth 客户端。`),
        );
      }

      const profileConfig = getClientProfileConfig(input.profile);
      try {
        validateConsentModeWithAudience(input.consentMode, detail.audience, profileConfig);
      } catch (error) {
        return Promise.reject(error);
      }

      const clientId = `${input.name.slice(0, 2).toLowerCase()}_${Math.random().toString(36).slice(2, 16)}`;
      const now = new Date().toISOString();

      const clientSecrets = profileConfig.clientType === "confidential"
        ? [{ secretId: `sec_${Math.random().toString(36).slice(2, 8)}`, label: "初始密钥", createdAt: now, lastRotatedAt: null }]
        : [];

      const client: OAuthClient = {
        clientId,
        applicationId: input.applicationId,
        name: input.name,
        clientType: profileConfig.clientType,
        grantTypes: [...profileConfig.grantTypes],
        tokenEndpointAuthMethod: profileConfig.tokenEndpointAuthMethod,
        redirectUris: buildRedirectUris(input.redirectUris, now),
        logoutUri: input.logoutUri || null,
        allowedScopes: resolveScopes(input.allowedScopes),
        consentMode: input.consentMode,
        status: "active",
        clientSecrets,
        createdAt: now,
        updatedAt: now,
      };

      detail.clients.push(client);
      detail.updatedAt = now;

      const app = applications.find((item) => item.applicationId === input.applicationId);
      if (app) {
        app.clientCount += 1;
        app.updatedAt = now;
      }

      const result: OAuthClientCreationResult = { clientId };
      if (profileConfig.clientType === "confidential") {
        result.clientSecret = `sec_${Math.random().toString(36).slice(2, 8)}${Math.random().toString(36).slice(2, 8)}${Math.random().toString(36).slice(2, 8)}`;
      }
      return Promise.resolve(result);
    },
    createApplicationWithInitialClient: (input: ApplicationWithInitialClientInput): Promise<ApplicationWithInitialClientResult> => {
      const profileConfig = getClientProfileConfig(input.initialClient.profile);
      try {
        validateApplicationCreateInput(input.application);
        validateOAuthClientCreateInput({
          applicationId: "__pending__",
          ...input.initialClient,
        });
        validateConsentModeWithAudience(
          input.initialClient.consentMode,
          input.application.audience,
          profileConfig,
        );
      } catch (error) {
        return Promise.reject(error);
      }

      const now = new Date().toISOString();
      const applicationId = `app_${Math.random().toString(36).slice(2, 10)}`;

      const detail: OAuthApplicationDetail = {
        applicationId,
        name: input.application.name,
        description: input.application.description,
        logoUrl: null,
        audience: input.application.audience,
        ownerId: input.application.ownerId,
        ownerName: resolveOwnerName(input.application.ownerId),
        status: "active",
        clients: [],
        grants: [],
        auditEntries: [
          { eventId: `app_evt_${Math.random().toString(36).slice(2, 8)}`, eventType: "应用创建", actorName: "林知行", occurredAt: now, result: "success" },
        ],
        createdAt: now,
        updatedAt: now,
      };

      applicationDetails[applicationId] = detail;

      const clientId = `${input.initialClient.name.slice(0, 2).toLowerCase()}_${Math.random().toString(36).slice(2, 16)}`;

      const clientSecrets = profileConfig.clientType === "confidential"
        ? [{ secretId: `sec_${Math.random().toString(36).slice(2, 8)}`, label: "初始密钥", createdAt: now, lastRotatedAt: null }]
        : [];

      const client: OAuthClient = {
        clientId,
        applicationId,
        name: input.initialClient.name,
        clientType: profileConfig.clientType,
        grantTypes: [...profileConfig.grantTypes],
        tokenEndpointAuthMethod: profileConfig.tokenEndpointAuthMethod,
        redirectUris: buildRedirectUris(input.initialClient.redirectUris, now),
        logoutUri: input.initialClient.logoutUri || null,
        allowedScopes: resolveScopes(input.initialClient.allowedScopes),
        consentMode: input.initialClient.consentMode,
        status: "active",
        clientSecrets,
        createdAt: now,
        updatedAt: now,
      };

      detail.clients.push(client);
      detail.auditEntries.push({
        eventId: `app_evt_${Math.random().toString(36).slice(2, 8)}`,
        eventType: "OAuth 客户端创建",
        actorName: "林知行",
        occurredAt: now,
        result: "success",
      });

      applications.unshift({
        applicationId,
        name: input.application.name,
        audience: input.application.audience,
        ownerId: input.application.ownerId,
        ownerName: detail.ownerName,
        status: "active",
        clientCount: 1,
        updatedAt: now,
      });

      const result: ApplicationWithInitialClientResult = { applicationId, clientId };
      if (profileConfig.clientType === "confidential") {
        result.clientSecret = `sec_${Math.random().toString(36).slice(2, 8)}${Math.random().toString(36).slice(2, 8)}${Math.random().toString(36).slice(2, 8)}`;
      }
      return Promise.resolve(result);
    },
    decideConsent: (_requestId: string, decision: ConsentDecision): Promise<{ redirectUrl: string }> => {
      const redirectUrl = decision === "allow"
        ? "https://workspace.united.example/callback"
        : "/account";
      return Promise.resolve({ redirectUrl });
    },
    revokeGrant: (grantId: string): Promise<void> => {
      const index = authorizedApplications.findIndex((grant) => grant.grantId === grantId);
      if (index !== -1) {
        authorizedApplications.splice(index, 1);
      }
      for (const detail of Object.values(applicationDetails)) {
        const grantIndex = detail.grants.findIndex((grant) => grant.grantId === grantId);
        if (grantIndex !== -1) {
          detail.grants[grantIndex] = { ...detail.grants[grantIndex], status: "revoked" as const };
        }
      }
      return Promise.resolve();
    },
    rotateClientSecret: (applicationId: string, clientId: string): Promise<SecretRotationResult> => {
      const now = new Date().toISOString();
      const expiryMs = Date.now() + 24 * 60 * 60 * 1000;
      const previousSecretExpiresAt = new Date(expiryMs).toISOString();

      // Mirrors the backend URL resource binding: the client must belong to
      // the addressed application, so lookups never cross applications.
      const detail = applicationDetails[applicationId];
      if (!detail) {
        return Promise.reject(new Error(`Application ${applicationId} not found.`));
      }
      const client = detail.clients.find((c) => c.clientId === clientId);
      if (!client) {
        return Promise.reject(
          new Error(`Client ${clientId} not found under application ${applicationId}.`),
        );
      }
      if (client.clientType !== "confidential") {
        return Promise.reject(new Error("Public clients do not use client secrets."));
      }
      const newSecretId = `sec_${Math.random().toString(36).slice(2, 8)}`;
      client.clientSecrets.push({
        secretId: newSecretId,
        label: `轮换密钥 ${new Date().toLocaleString("zh-CN")}`,
        createdAt: now,
        lastRotatedAt: now,
      });
      client.updatedAt = now;
      detail.updatedAt = now;

      const newSecret = `sec_${Math.random().toString(36).slice(2, 8)}${Math.random().toString(36).slice(2, 8)}${Math.random().toString(36).slice(2, 8)}`;
      return Promise.resolve({
        secretId: newSecretId,
        clientSecret: newSecret,
        previousSecretExpiresAt,
      });
    },
    updateApplicationStatus: (applicationId: string, status: ApplicationStatus): Promise<void> => {
      const now = new Date().toISOString();
      const detail = applicationDetails[applicationId];
      if (!detail) {
        return Promise.reject(new Error(`Application ${applicationId} not found.`));
      }
      detail.status = status;
      detail.updatedAt = now;
      detail.auditEntries.push({
        eventId: `app_evt_${Math.random().toString(36).slice(2, 8)}`,
        eventType: status === "disabled" ? "应用停用" : "应用启用",
        actorName: "林知行",
        occurredAt: now,
        result: "success",
      });

      const app = applications.find((item) => item.applicationId === applicationId);
      if (app) {
        app.status = status;
        app.updatedAt = now;
      }
      return Promise.resolve();
    },
    deleteApplication: (applicationId: string): Promise<void> => {
      delete applicationDetails[applicationId];
      const index = applications.findIndex((item) => item.applicationId === applicationId);
      if (index !== -1) {
        applications.splice(index, 1);
      }
      return Promise.resolve();
    },
    updateApplication: (applicationId: string, input: ApplicationUpdateInput): Promise<void> => {
      const now = new Date().toISOString();
      const detail = applicationDetails[applicationId];
      if (!detail) {
        return Promise.reject(new Error(`Application ${applicationId} not found.`));
      }
      if (input.name !== undefined) detail.name = input.name;
      if (input.description !== undefined) detail.description = input.description;
      if (input.audience !== undefined) detail.audience = input.audience;
      if (input.ownerId !== undefined) {
        detail.ownerId = input.ownerId;
        detail.ownerName = resolveOwnerName(input.ownerId);
      }
      detail.updatedAt = now;

      const app = applications.find((item) => item.applicationId === applicationId);
      if (app) {
        if (input.name !== undefined) app.name = input.name;
        if (input.audience !== undefined) app.audience = input.audience;
        if (input.ownerId !== undefined) {
          app.ownerId = input.ownerId;
          app.ownerName = detail.ownerName;
        }
        app.updatedAt = now;
      }
      return Promise.resolve();
    },
    getPolicies: (query?: PageQuery) => Promise.resolve(toCursorPage(policies, query)),
    getPolicyDetail: (policyId: string): Promise<PolicyDetail | null> => {
      const detail = policyDetails[policyId];
      if (!detail) return Promise.resolve(null);
      return Promise.resolve({ ...detail, principals: [...detail.principals], conditions: [...detail.conditions], versionHistory: [...detail.versionHistory] });
    },
    getAuditEvents: (query?: AuditQuery) => Promise.resolve(filterAuditEvents(auditEvents, query)),

    exportAuditEvents: (query: AuditQuery): Promise<AuditExportResult> => {
      const filtered = filterAuditEvents(auditEvents, query);
      const now = new Date().toISOString();
      return Promise.resolve({
        exportId: `export_${Date.now().toString(36)}`,
        status: "completed",
        downloadUrl: null,
        requestedAt: now,
        completedAt: now,
        totalEvents: filtered.items.length,
      });
    },

    updateProfile: (input: { displayName?: string; nickname?: string }): Promise<void> => {
      if (input.displayName !== undefined) {
        employeeAdminUser.displayName = input.displayName;
      }
      if (input.nickname !== undefined) {
        employeeAdminUser.nickname = input.nickname;
      }
      return Promise.resolve();
    },
    uploadAvatar: (): Promise<{ avatarUrl: string }> =>
      Promise.resolve({ avatarUrl: "https://example.com/avatar/mock.png" }),
    requestEmailChange: (): Promise<{ requestId: string }> =>
      Promise.resolve({ requestId: `req_email_${Math.random().toString(36).slice(2, 10)}` }),
    verifyEmailChange: (): Promise<void> => Promise.resolve(),
    requestPhoneChange: (): Promise<{ requestId: string }> =>
      Promise.resolve({ requestId: `req_phone_${Math.random().toString(36).slice(2, 10)}` }),
    verifyPhoneChange: (): Promise<void> => Promise.resolve(),
    changePassword: (): Promise<void> => Promise.resolve(),
    enrollTotp: (): Promise<{ secret: string; qrCodeUrl: string }> =>
      Promise.resolve({
        secret: "JBSWY3DPEHPK3PXP MOCKSECRET==",
        qrCodeUrl: "https://example.com/totp/qr/mock",
      }),
    confirmTotpEnrollment: (): Promise<void> => Promise.resolve(),
    removeTotp: (): Promise<void> => Promise.resolve(),
    requestReauthentication: (): Promise<{ status: "granted"; reauthToken: string; expiresAt: string }> =>
      Promise.resolve({ status: "granted", reauthToken: "mock-reauth-token", expiresAt: "2026-08-09T12:00:00Z" }),
    completeReauthenticationMfa: (): Promise<{ status: "granted"; reauthToken: string; expiresAt: string }> =>
      Promise.resolve({ status: "granted", reauthToken: "mock-reauth-token", expiresAt: "2026-08-09T12:00:00Z" }),
    startPasskeyEnrollment: () => Promise.resolve({
      enrollmentToken: "mock-enrollment-token",
      passkeyId: "mock-passkey-id",
      publicKeyCredentialCreationOptions: {},
    }),
    completePasskeyEnrollment: (input) => Promise.resolve({ status: "confirmed", passkeyId: input.passkeyId }),
    cancelPasskeyEnrollment: (): Promise<void> => Promise.resolve(),
    removePasskey: () => Promise.resolve(securitySummary),
    generateRecoveryCodes: (): Promise<{ codes: string[] }> =>
      Promise.resolve({
        codes: [
          "mock-rc-01-a3f9",
          "mock-rc-02-b7e1",
          "mock-rc-03-c2d4",
          "mock-rc-04-e8f6",
          "mock-rc-05-a1b3",
          "mock-rc-06-c5d7",
          "mock-rc-07-e9f2",
          "mock-rc-08-b4a8",
        ],
      }),
    revokeOtherSessions: (): Promise<void> => {
      const currentSession = sessions.find((session) => session.isCurrent);
      sessions.length = 0;
      if (currentSession) {
        sessions.push(currentSession);
      }
      return Promise.resolve();
    },
    logout: (): Promise<void> => Promise.resolve(),
    revokeSession: (sessionId: string): Promise<void> => {
      const index = sessions.findIndex((session) => session.sessionId === sessionId);
      if (index !== -1) {
        sessions.splice(index, 1);
      }
      return Promise.resolve();
    },

    updateUserStatus: (userId: string, status: "active" | "disabled"): Promise<void> => {
      const user = users.find((u) => u.userId === userId);
      if (user) {
        user.status = status;
      }
      const detail = userDetails[userId];
      if (detail) {
        detail.status = status;
      }
      return Promise.resolve();
    },

    revokeUserSessions: (userId: string): Promise<void> => {
      void userId;
      return Promise.resolve();
    },

    linkEmployeeProfile: (input: EmployeeLinkInput): Promise<void> => {
      void input;
      return Promise.resolve();
    },

    offboardEmployee: (userId: string): Promise<void> => {
      const detail = employeeDetails[userId];
      if (detail) {
        detail.status = "offboarding";
      }
      const employee = employees.find((e) => e.userId === userId);
      if (employee) {
        employee.status = "offboarding";
      }
      return Promise.resolve();
    },

    savePolicyDraft: (input: PolicyDraftInput): Promise<{ policyId: string; version: number }> => {
      const now = new Date().toISOString();
      if (input.policyId) {
        const existing = policyDetails[input.policyId];
        if (existing) {
          const nextVersion = existing.version + 1;
          existing.name = input.name;
          existing.description = input.description;
          existing.resource = input.resource;
          existing.action = input.action;
          existing.effect = input.effect;
          existing.principals = [...input.principals];
          existing.conditions = [...input.conditions];
          existing.version = nextVersion;
          existing.status = "draft";
          existing.updatedBy = "当前管理员";
          existing.updatedAt = now;
          existing.versionHistory.unshift({
            version: nextVersion,
            status: "draft",
            updatedBy: "当前管理员",
            updatedAt: now,
            changeSummary: "编辑草稿",
          });

          const summary = policies.find((p) => p.policyId === input.policyId);
          if (summary) {
            summary.version = nextVersion;
            summary.status = "draft";
            summary.updatedBy = "当前管理员";
            summary.updatedAt = now;
          }

          return Promise.resolve({ policyId: input.policyId, version: nextVersion });
        }
      }

      const newPolicyId = `pol_${Date.now().toString(36)}`;
      const newDetail: PolicyDetail = {
        policyId: newPolicyId,
        name: input.name,
        description: input.description,
        resource: input.resource,
        action: input.action,
        effect: input.effect,
        version: 1,
        status: "draft",
        principals: [...input.principals],
        conditions: [...input.conditions],
        updatedBy: "当前管理员",
        updatedAt: now,
        versionHistory: [
          { version: 1, status: "draft", updatedBy: "当前管理员", updatedAt: now, changeSummary: "草稿创建" },
        ],
      };
      policyDetails[newPolicyId] = newDetail;
      policies.push({
        policyId: newPolicyId,
        name: input.name,
        resource: input.resource,
        version: 1,
        status: "draft",
        updatedBy: "当前管理员",
        updatedAt: now,
      });

      return Promise.resolve({ policyId: newPolicyId, version: 1 });
    },

    publishPolicy: (policyId: string): Promise<{ version: number }> => {
      const detail = policyDetails[policyId];
      if (!detail) {
        return Promise.reject(new Error("策略不存在"));
      }
      detail.status = "published";
      detail.updatedAt = new Date().toISOString();
      detail.versionHistory.unshift({
        version: detail.version,
        status: "published",
        updatedBy: "当前管理员",
        updatedAt: detail.updatedAt,
        changeSummary: `发布版本 v${detail.version}`,
      });

      const summary = policies.find((p) => p.policyId === policyId);
      if (summary) {
        summary.status = "published";
        summary.updatedAt = detail.updatedAt;
        summary.updatedBy = "当前管理员";
      }

      return Promise.resolve({ version: detail.version });
    },

    simulatePolicy: (input: PolicySimulationInput): Promise<PolicySimulationResult> => {
      const now = new Date().toISOString();
      const role = input.principalAttributes["role"] ?? "";
      const department = input.principalAttributes["department"] ?? "";

      for (const policyId of Object.keys(policyDetails)) {
        const detail = policyDetails[policyId];
        if (detail.action !== input.action) continue;
        if (detail.effect !== "allow") continue;

        const principalMatch = detail.principals.every((p) => {
          const attrValue = p.attribute === "role" ? role : department;
          if (p.operator === "eq") return attrValue === p.value;
          if (p.operator === "in") return p.value.split(",").map((v) => v.trim()).includes(attrValue);
          if (p.operator === "neq") return attrValue !== p.value;
          return false;
        });

        if (principalMatch) {
          return Promise.resolve({
            decision: "allow",
            matchedPolicyId: detail.policyId,
            matchedPolicyName: detail.name,
            evaluatedAt: now,
            reasons: [
              `Principal 属性匹配：role=${role}, department=${department}`,
              `策略效果：${detail.effect}`,
              `资源：${detail.resource}`,
              `操作：${detail.action}`,
            ],
          });
        }
      }

      return Promise.resolve({
        decision: "deny",
        matchedPolicyId: null,
        matchedPolicyName: null,
        evaluatedAt: now,
        reasons: [
          `未找到匹配的允许策略`,
          `Principal 属性：role=${role}, department=${department}`,
          `操作：${input.action}`,
        ],
      });
    },

    syncProviderDirectory: (providerId: string): Promise<DirectorySyncResult> => {
      const now = new Date().toISOString();
      const result: DirectorySyncResult = {
        syncId: `sync_${Date.now().toString(36)}`,
        startedAt: now,
        completedAt: now,
        status: "partial",
        departmentsAdded: 8,
        departmentsUpdated: 2,
        employeesAdded: 32,
        employeesUpdated: 5,
        employeesOffboarded: 1,
        conflictsDetected: syncConflicts.filter((c) => c.providerId === providerId && c.status === "pending").length,
      };

      const detail = providerDetails[providerId];
      if (detail) {
        detail.lastSyncAt = now;
        detail.lastSyncResult = result;
      }

      syncHistory.unshift({
        syncId: result.syncId,
        providerId,
        startedAt: result.startedAt,
        completedAt: result.completedAt,
        status: result.status,
        summary: `新增 ${result.departmentsAdded} 个部门，更新 ${result.departmentsUpdated} 个，新增 ${result.employeesAdded} 名员工，检测到 ${result.conflictsDetected} 个冲突`,
      });

      return Promise.resolve(result);
    },

    resolveSyncConflict: (conflictId: string, userId: string): Promise<void> => {
      const conflict = syncConflicts.find((c) => c.conflictId === conflictId);
      if (conflict) {
        conflict.status = "resolved";
        conflict.matchedUserId = userId;
        conflict.matchReason = "manual";
      }
      return Promise.resolve();
    },

    ignoreSyncConflict: (conflictId: string): Promise<void> => {
      const conflict = syncConflicts.find((c) => c.conflictId === conflictId);
      if (conflict) {
        conflict.status = "ignored";
      }
      return Promise.resolve();
    },
  };
}

export const mockUnitedPassDataSource: UnitedPassDataSource = createMockUnitedPassDataSource();
