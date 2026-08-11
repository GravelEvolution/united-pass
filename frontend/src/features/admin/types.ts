//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Admin feature contract types
//

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
  actorId: string;
  targetLabel: string;
  targetId: string;
  occurredAt: string;
  result: "success" | "denied";
  requestId: string;
  details: string;
};

export type AuditQuery = {
  cursor?: string;
  limit?: number;
  query?: string;
  eventType?: string;
  result?: string;
  actorName?: string;
  requestId?: string;
  from?: string;
  to?: string;
};

export type AuditExportResult = {
  exportId: string;
  status: "pending" | "processing" | "completed" | "failed";
  downloadUrl: string | null;
  requestedAt: string;
  completedAt: string | null;
  totalEvents: number;
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
  supervisorUserId: string | null;
  supervisorName: string | null;
  onboardedAt: string;
  linkedConsumerAccount: boolean;
};

export type DepartmentDetail = {
  departmentId: string;
  name: string;
  parentDepartmentId: string | null;
  parentName: string | null;
  ownerUserId: string | null;
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

export type EmployeeProfileInput = {
  departmentId: string;
  title: string;
  supervisorUserId?: string;
};

export type DepartmentInput = {
  name: string;
  parentDepartmentId?: string;
  ownerUserId?: string;
};

export type DepartmentPatch = {
  name?: string;
  parentDepartmentId?: string | null;
  ownerUserId?: string | null;
};

export type ProviderDetail = {
  providerId: string;
  displayName: string;
  vendor: "feishu" | "generic";
  status: "planned" | "active" | "disabled";
  loginEnabled: boolean;
  appId: string;
  secretConfigured: boolean;
  callbackUrl: string;
  contactScope: string;
  linkedUserCount: number;
  lastValidatedAt: string | null;
  lastSyncAt: string | null;
  lastSyncResult: DirectorySyncResult | null;
  updatedAt: string;
};

export type DirectorySyncResult = {
  syncId: string;
  startedAt: string;
  completedAt: string | null;
  status: "pending" | "running" | "success" | "partial" | "failed";
  departmentsAdded: number;
  departmentsUpdated: number;
  employeesAdded: number;
  employeesUpdated: number;
  employeesOffboarded: number;
  conflictsDetected: number;
};

export type SyncConflict = {
  conflictId: string;
  providerId: string;
  externalSubject: string;
  externalName: string;
  externalEmail: string;
  matchedUserId: string | null;
  matchedUserName: string | null;
  matchReason: "email" | "name" | "manual";
  status: "pending" | "resolved" | "ignored";
  detectedAt: string;
};

export type DirectorySyncHistoryEntry = {
  syncId: string;
  providerId: string;
  startedAt: string;
  completedAt: string | null;
  status: "pending" | "running" | "success" | "partial" | "failed";
  summary: string;
};
