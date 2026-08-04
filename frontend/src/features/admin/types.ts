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

export type AuditEvent = {
  eventId: string;
  eventType: string;
  actorName: string;
  targetLabel: string;
  occurredAt: string;
  result: "success" | "denied";
};
