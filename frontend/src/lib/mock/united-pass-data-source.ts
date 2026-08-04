import type { UnitedPassDataSource } from "@/lib/api/united-pass-data-source";
import { SYSTEM_NAME } from "@/lib/branding";
import type { AuthorizedApplication } from "@/features/account/types";
import type {
  AllowedScope,
  ApplicationCreateInput,
  ApplicationCreationResult,
  ApplicationStatus,
  ApplicationUpdateInput,
  OAuthApplication,
  OAuthApplicationDetail,
  OAuthClient,
  OAuthClientCreateInput,
  OAuthClientCreationResult,
  SecretRotationResult,
} from "@/features/applications/types";
import { getClientProfileConfig } from "@/features/applications/types";
import type { ConsentDecision, ConsentResolution, ConsentRequest } from "@/features/authorization/types";

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
} satisfies Awaited<ReturnType<UnitedPassDataSource["getAdminCurrentUser"]>>;

const securityFactors = [
  { factorId: "factor_password", kind: "password", label: "账户密码", status: "active", updatedAt: "2026-07-12T03:20:00Z" },
  { factorId: "factor_totp", kind: "totp", label: "身份验证器", status: "active", updatedAt: "2026-06-02T09:10:00Z" },
  { factorId: "factor_passkey", kind: "passkey", label: "通行密钥", status: "recommended" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getSecurityFactors"]>>;

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

const mutableAuthorizedApplications: AuthorizedApplication[] = [...initialAuthorizedApplications];

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
] satisfies Awaited<ReturnType<UnitedPassDataSource["getUsers"]>>;

const employees = [
  { userId: employeeAdminUser.userId, displayName: "林知行", employeeId: "UP-1042", departmentName: "身份平台", title: "产品设计师", status: "active" },
  { userId: "usr_02F4PXKQ0EZP5F7B9V3C", displayName: "周予安", employeeId: "UP-0928", departmentName: "基础架构", title: "高级工程师", status: "active" },
  { userId: "usr_05QG6E8W4NR7Y2Z1PC9S", displayName: "顾言", employeeId: "UP-0815", departmentName: "客户成功", title: "客户成功经理", status: "offboarding" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getEmployees"]>>;

const departments = [
  { departmentId: "dep_identity", name: "身份平台", parentName: "产品与体验", memberCount: 18, ownerName: "许清和" },
  { departmentId: "dep_infra", name: "基础架构", parentName: "技术中心", memberCount: 32, ownerName: "程越" },
  { departmentId: "dep_success", name: "客户成功", parentName: "商业化中心", memberCount: 24, ownerName: "沈叙" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getDepartments"]>>;

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
] satisfies Awaited<ReturnType<UnitedPassDataSource["getIdentityProviders"]>>;

const initialApplications = [
  { applicationId: "app_workspace", name: "United Workspace", audience: "external", ownerName: "协作产品团队", status: "active", clientCount: 1, updatedAt: "2026-08-01T06:10:00Z" },
  { applicationId: "app_mobile", name: "United Mobile", audience: "external", ownerName: "移动端团队", status: "active", clientCount: 1, updatedAt: "2026-07-28T02:32:00Z" },
  { applicationId: "app_legacy", name: "Legacy Reports", audience: "internal", ownerName: "数据团队", status: "disabled", clientCount: 1, updatedAt: "2026-06-16T12:00:00Z" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getApplications"]>>;

const mutableApplications: OAuthApplication[] = [...initialApplications];

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
        consentMode: "trusted_first_party",
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

const mutableApplicationDetails: Record<string, OAuthApplicationDetail> = { ...initialApplicationDetails };

const policies = [
  { policyId: "pol_application_manage", name: "应用管理员维护 OAuth 应用", resource: "application:*", version: 7, status: "published", updatedBy: "周予安", updatedAt: "2026-08-03T07:45:00Z" },
  { policyId: "pol_employee_read", name: "部门负责人查看直属员工", resource: "employee:*", version: 3, status: "published", updatedBy: "林知行", updatedAt: "2026-07-30T03:20:00Z" },
  { policyId: "pol_audit_export", name: "安全审计导出限制", resource: "audit:export", version: 1, status: "draft", updatedBy: "程越", updatedAt: "2026-08-04T01:14:00Z" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getPolicies"]>>;

const auditEvents = [
  { eventId: "evt_001", eventType: "用户登录", actorName: "林知行", targetLabel: SYSTEM_NAME, occurredAt: "2026-08-04T05:42:00Z", result: "success" },
  { eventId: "evt_002", eventType: "策略发布", actorName: "周予安", targetLabel: "应用管理员维护 OAuth 应用", occurredAt: "2026-08-03T07:45:00Z", result: "success" },
  { eventId: "evt_003", eventType: "管理操作拒绝", actorName: "陈默", targetLabel: "员工目录", occurredAt: "2026-08-03T02:18:00Z", result: "denied" },
  { eventId: "evt_004", eventType: "会话撤销", actorName: "林知行", targetLabel: "Windows 设备", occurredAt: "2026-08-02T10:07:00Z", result: "success" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getAuditEvents"]>>;

function resolveScopes(scopeIds: string[]): AllowedScope[] {
  const scopeMap = new Map(availableScopes.map((scope) => [scope.scope, scope]));
  return scopeIds
    .map((scopeId) => scopeMap.get(scopeId))
    .filter((scope): scope is AllowedScope => scope !== undefined);
}

function buildRedirectUris(uris: string[], now: string) {
  return uris.map((uri) => ({
    uri,
    isLoopback: uri.startsWith("http://localhost") || uri.startsWith("http://127.0.0.1"),
    addedAt: now,
  }));
}

export const mockUnitedPassDataSource: UnitedPassDataSource = {
  getCurrentUser: () => Promise.resolve(externalAppUser),
  getAdminCurrentUser: () => Promise.resolve(employeeAdminUser),
  getSecurityFactors: () => Promise.resolve(securityFactors),
  getSessions: () => Promise.resolve(sessions),
  getConsentRequest: () => Promise.resolve(consentRequest),
  getConsentResolution: (requestId: string) => {
    const resolution = consentResolutions[requestId];
    if (resolution) {
      return Promise.resolve(resolution);
    }
    return Promise.resolve({ status: "client_not_found", requestId });
  },
  getAuthorizedApplications: () => Promise.resolve(mutableAuthorizedApplications),
  getAdminDashboard: () => Promise.resolve({
    metrics: [
      { label: "活跃用户", value: "12,840", change: "近 30 天 +8.4%", tone: "positive" },
      { label: "员工账户", value: "486", change: "3 个待完成入职", tone: "attention" },
      { label: "OAuth 应用", value: "24", change: "22 个正常运行", tone: "neutral" },
      { label: "高风险事件", value: "2", change: "需要安全团队复核", tone: "attention" },
    ],
    recentEvents: auditEvents.slice(0, 3),
  }),
  getUsers: () => Promise.resolve(users),
  getEmployees: () => Promise.resolve(employees),
  getDepartments: () => Promise.resolve(departments),
  getIdentityProviders: () => Promise.resolve(identityProviders),
  getApplications: () => Promise.resolve(mutableApplications),
  getApplicationDetail: (applicationId: string) => {
    const detail = mutableApplicationDetails[applicationId];
    return Promise.resolve(detail ?? null);
  },
  getAvailableScopes: () => Promise.resolve(availableScopes),
  createApplication: (input: ApplicationCreateInput): Promise<ApplicationCreationResult> => {
    const applicationId = `app_${Math.random().toString(36).slice(2, 10)}`;
    const now = new Date().toISOString();

    const detail: OAuthApplicationDetail = {
      applicationId,
      name: input.name,
      description: input.description,
      logoUrl: null,
      audience: input.audience,
      ownerId: `owner_${Math.random().toString(36).slice(2, 10)}`,
      ownerName: input.ownerName,
      status: "active",
      clients: [],
      grants: [],
      auditEntries: [
        { eventId: `app_evt_${Math.random().toString(36).slice(2, 8)}`, eventType: "应用创建", actorName: "林知行", occurredAt: now, result: "success" },
      ],
      createdAt: now,
      updatedAt: now,
    };

    mutableApplicationDetails[applicationId] = detail;
    mutableApplications.unshift({
      applicationId,
      name: input.name,
      audience: input.audience,
      ownerName: input.ownerName,
      status: "active",
      clientCount: 0,
      updatedAt: now,
    });

    return Promise.resolve({ applicationId });
  },
  createOAuthClient: (input: OAuthClientCreateInput): Promise<OAuthClientCreationResult> => {
    const profileConfig = getClientProfileConfig(input.profile);
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

    const detail = mutableApplicationDetails[input.applicationId];
    if (detail) {
      detail.clients.push(client);
      detail.updatedAt = now;
    }

    const app = mutableApplications.find((item) => item.applicationId === input.applicationId);
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
  decideConsent: (_requestId: string, decision: ConsentDecision): Promise<{ redirectUrl: string }> => {
    const redirectUrl = decision === "allow"
      ? "https://workspace.united.example/callback"
      : "/account";
    return Promise.resolve({ redirectUrl });
  },
  revokeGrant: (grantId: string): Promise<void> => {
    const index = mutableAuthorizedApplications.findIndex((grant) => grant.grantId === grantId);
    if (index !== -1) {
      mutableAuthorizedApplications.splice(index, 1);
    }
    for (const detail of Object.values(mutableApplicationDetails)) {
      const grantIndex = detail.grants.findIndex((grant) => grant.grantId === grantId);
      if (grantIndex !== -1) {
        detail.grants[grantIndex] = { ...detail.grants[grantIndex], status: "revoked" as const };
      }
    }
    return Promise.resolve();
  },
  rotateClientSecret: (clientId: string): Promise<SecretRotationResult> => {
    const now = new Date().toISOString();
    const expiryMs = Date.now() + 24 * 60 * 60 * 1000;
    const previousSecretExpiresAt = new Date(expiryMs).toISOString();

    for (const detail of Object.values(mutableApplicationDetails)) {
      const client = detail.clients.find((c) => c.clientId === clientId);
      if (client) {
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
      }
    }
    return Promise.reject(new Error(`Client ${clientId} not found.`));
  },
  updateApplicationStatus: (applicationId: string, status: ApplicationStatus): Promise<void> => {
    const now = new Date().toISOString();
    const detail = mutableApplicationDetails[applicationId];
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

    const app = mutableApplications.find((item) => item.applicationId === applicationId);
    if (app) {
      app.status = status;
      app.updatedAt = now;
    }
    return Promise.resolve();
  },
  deleteApplication: (applicationId: string): Promise<void> => {
    delete mutableApplicationDetails[applicationId];
    const index = mutableApplications.findIndex((item) => item.applicationId === applicationId);
    if (index !== -1) {
      mutableApplications.splice(index, 1);
    }
    return Promise.resolve();
  },
  updateApplication: (applicationId: string, input: ApplicationUpdateInput): Promise<void> => {
    const now = new Date().toISOString();
    const detail = mutableApplicationDetails[applicationId];
    if (!detail) {
      return Promise.reject(new Error(`Application ${applicationId} not found.`));
    }
    if (input.name !== undefined) detail.name = input.name;
    if (input.description !== undefined) detail.description = input.description;
    if (input.audience !== undefined) detail.audience = input.audience;
    if (input.ownerName !== undefined) detail.ownerName = input.ownerName;
    detail.updatedAt = now;

    const app = mutableApplications.find((item) => item.applicationId === applicationId);
    if (app) {
      if (input.name !== undefined) app.name = input.name;
      if (input.audience !== undefined) app.audience = input.audience;
      if (input.ownerName !== undefined) app.ownerName = input.ownerName;
      app.updatedAt = now;
    }
    return Promise.resolve();
  },
  getPolicies: () => Promise.resolve(policies),
  getAuditEvents: () => Promise.resolve(auditEvents),
};
