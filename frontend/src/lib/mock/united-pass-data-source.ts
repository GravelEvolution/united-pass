import type { UnitedPassDataSource } from "@/lib/api/united-pass-data-source";

const currentUser = {
  userId: "usr_01JUP8M8B4Q7R4T6PK1D",
  displayName: "林知行",
  email: "zhixing.lin@example.com",
  phoneMasked: "+86 138 **** 5621",
  personas: ["consumer", "employee"],
  employeeProfile: {
    employeeId: "UP-1042",
    departmentName: "产品与体验 / 身份平台",
    title: "产品设计师",
  },
} satisfies Awaited<ReturnType<UnitedPassDataSource["getCurrentUser"]>>;

const securityFactors = [
  { factorId: "factor_password", kind: "password", label: "账户密码", status: "active", updatedAt: "2026-07-12T03:20:00Z" },
  { factorId: "factor_totp", kind: "totp", label: "身份验证器", status: "active", updatedAt: "2026-06-02T09:10:00Z" },
  { factorId: "factor_passkey", kind: "passkey", label: "通行密钥", status: "recommended" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getSecurityFactors"]>>;

const sessions = [
  { sessionId: "ses_current", deviceName: "MacBook Pro", clientName: "Chrome 138 · macOS", approximateLocation: "上海市", ipAddressMasked: "203.0.113.*", lastActiveAt: "2026-08-04T05:42:00Z", isCurrent: true },
  { sessionId: "ses_mobile", deviceName: "iPhone 17", clientName: "United Pass · iOS", approximateLocation: "上海市", ipAddressMasked: "198.51.100.*", lastActiveAt: "2026-08-03T13:16:00Z", isCurrent: false },
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
} satisfies Awaited<ReturnType<UnitedPassDataSource["getConsentRequest"]>>;

const users = [
  { userId: "usr_01JUP8M8B4Q7R4T6PK1D", displayName: "林知行", email: "zhixing.lin@example.com", personaLabel: "外部用户 · 员工", status: "active", lastActiveAt: "2026-08-04T05:42:00Z" },
  { userId: "usr_02F4PXKQ0EZP5F7B9V3C", displayName: "周予安", email: "yuan.zhou@example.com", personaLabel: "员工", status: "active", lastActiveAt: "2026-08-04T04:18:00Z" },
  { userId: "usr_03D1KMM3AGX8G2QW5T9N", displayName: "陈默", email: "mo.chen@example.net", personaLabel: "外部用户", status: "pending", lastActiveAt: "2026-08-02T11:03:00Z" },
  { userId: "usr_04ABT7S6HHQ1N8K2YM0E", displayName: "苏晚", email: "wan.su@example.org", personaLabel: "外部用户", status: "disabled", lastActiveAt: "2026-07-21T08:44:00Z" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getUsers"]>>;

const employees = [
  { userId: users[0].userId, displayName: "林知行", employeeId: "UP-1042", departmentName: "身份平台", title: "产品设计师", status: "active" },
  { userId: users[1].userId, displayName: "周予安", employeeId: "UP-0928", departmentName: "基础架构", title: "高级工程师", status: "active" },
  { userId: "usr_05QG6E8W4NR7Y2Z1PC9S", displayName: "顾言", employeeId: "UP-0815", departmentName: "客户成功", title: "客户成功经理", status: "offboarding" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getEmployees"]>>;

const departments = [
  { departmentId: "dep_identity", name: "身份平台", parentName: "产品与体验", memberCount: 18, ownerName: "许清和" },
  { departmentId: "dep_infra", name: "基础架构", parentName: "技术中心", memberCount: 32, ownerName: "程越" },
  { departmentId: "dep_success", name: "客户成功", parentName: "商业化中心", memberCount: 24, ownerName: "沈叙" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getDepartments"]>>;

const applications = [
  { applicationId: "app_workspace", name: "United Workspace", clientType: "confidential", ownerName: "协作产品团队", status: "active", redirectUriCount: 3, updatedAt: "2026-08-01T06:10:00Z" },
  { applicationId: "app_mobile", name: "United Mobile", clientType: "public", ownerName: "移动端团队", status: "active", redirectUriCount: 2, updatedAt: "2026-07-28T02:32:00Z" },
  { applicationId: "app_legacy", name: "Legacy Reports", clientType: "confidential", ownerName: "数据团队", status: "disabled", redirectUriCount: 1, updatedAt: "2026-06-16T12:00:00Z" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getApplications"]>>;

const policies = [
  { policyId: "pol_application_manage", name: "应用管理员维护 OAuth 应用", resource: "application:*", version: 7, status: "published", updatedBy: "周予安", updatedAt: "2026-08-03T07:45:00Z" },
  { policyId: "pol_employee_read", name: "部门负责人查看直属员工", resource: "employee:*", version: 3, status: "published", updatedBy: "林知行", updatedAt: "2026-07-30T03:20:00Z" },
  { policyId: "pol_audit_export", name: "安全审计导出限制", resource: "audit:export", version: 1, status: "draft", updatedBy: "程越", updatedAt: "2026-08-04T01:14:00Z" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getPolicies"]>>;

const auditEvents = [
  { eventId: "evt_001", eventType: "用户登录", actorName: "林知行", targetLabel: "United Pass", occurredAt: "2026-08-04T05:42:00Z", result: "success" },
  { eventId: "evt_002", eventType: "策略发布", actorName: "周予安", targetLabel: "应用管理员维护 OAuth 应用", occurredAt: "2026-08-03T07:45:00Z", result: "success" },
  { eventId: "evt_003", eventType: "管理操作拒绝", actorName: "陈默", targetLabel: "员工目录", occurredAt: "2026-08-03T02:18:00Z", result: "denied" },
  { eventId: "evt_004", eventType: "会话撤销", actorName: "林知行", targetLabel: "Windows 设备", occurredAt: "2026-08-02T10:07:00Z", result: "success" },
] satisfies Awaited<ReturnType<UnitedPassDataSource["getAuditEvents"]>>;

export const mockUnitedPassDataSource: UnitedPassDataSource = {
  getCurrentUser: () => Promise.resolve(currentUser),
  getSecurityFactors: () => Promise.resolve(securityFactors),
  getSessions: () => Promise.resolve(sessions),
  getConsentRequest: () => Promise.resolve(consentRequest),
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
  getApplications: () => Promise.resolve(applications),
  getPolicies: () => Promise.resolve(policies),
  getAuditEvents: () => Promise.resolve(auditEvents),
};
