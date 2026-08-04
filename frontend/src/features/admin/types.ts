export type DashboardMetric = {
  label: string;
  value: string;
  change: string;
  tone: "neutral" | "positive" | "attention";
};

export type ManagedUser = {
  userId: string;
  displayName: string;
  email: string;
  personaLabel: string;
  status: "active" | "disabled" | "pending";
  lastActiveAt: string;
};

export type EmployeeRecord = {
  userId: string;
  displayName: string;
  employeeId: string;
  departmentName: string;
  title: string;
  status: "active" | "offboarding";
};

export type DepartmentRecord = {
  departmentId: string;
  name: string;
  parentName: string;
  memberCount: number;
  ownerName: string;
};

export type IdentityProviderRecord = {
  providerId: string;
  displayName: string;
  vendor: "feishu" | "generic";
  integrationLabel: string;
  status: "planned" | "active" | "disabled";
  loginEnabled: boolean;
  linkedUserCount: number;
  updatedAt: string;
};

export type AuditEvent = {
  eventId: string;
  eventType: string;
  actorName: string;
  targetLabel: string;
  occurredAt: string;
  result: "success" | "denied";
};

export type UserDetail = {
  userId: string;
  displayName: string;
  email: string;
  phoneMasked: string;
  personaLabel: string;
  status: "active" | "disabled" | "pending";
  lastActiveAt: string;
  personas: ("consumer" | "employee")[];
  employeeProfile?: {
    employeeId: string;
    departmentName: string;
    title: string;
  };
  linkedIdentities: Array<{
    providerId: string;
    providerName: string;
    externalSubject: string;
    linkedAt: string;
  }>;
  activeSessions: Array<{
    sessionId: string;
    deviceName: string;
    lastActiveAt: string;
    isCurrent: boolean;
  }>;
  authorizedApplications: Array<{
    applicationName: string;
    scopes: string[];
    grantedAt: string;
    status: "active" | "revoked";
  }>;
  recentAuditEvents: AuditEvent[];
};

export type EmployeeDetail = {
  userId: string;
  displayName: string;
  email: string;
  employeeId: string;
  departmentName: string;
  departmentId: string;
  title: string;
  status: "active" | "offboarding";
  supervisorName: string | null;
  onboardedAt: string;
  linkedConsumerAccount: boolean;
};

export type DepartmentDetail = {
  departmentId: string;
  name: string;
  parentDepartmentId: string | null;
  parentName: string | null;
  ownerName: string;
  memberCount: number;
  childDepartments: Array<{
    departmentId: string;
    name: string;
    memberCount: number;
  }>;
  members: Array<{
    userId: string;
    displayName: string;
    title: string;
    employeeId: string;
  }>;
};

export type EmployeeLinkInput = {
  userId: string;
  departmentId: string;
  title: string;
  supervisorUserId?: string;
};
