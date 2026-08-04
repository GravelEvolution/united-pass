/**
 * Permission capabilities returned by the backend.
 *
 * Frontend uses these to filter navigation and control availability.
 * Every protected action must also be enforced by the backend via ABAC.
 *
 * See docs/api-contracts.md § 权限能力 for the full contract.
 */

export type PermissionCapabilities = {
  userRead: boolean;
  userDisable: boolean;
  employeeManage: boolean;
  employeeOffboard: boolean;
  departmentManage: boolean;
  applicationRead: boolean;
  applicationManage: boolean;
  applicationSecretRotate: boolean;
  policyRead: boolean;
  policyManage: boolean;
  policyPublish: boolean;
  auditRead: boolean;
  auditExport: boolean;
  providerRead: boolean;
  providerManage: boolean;
};

/** Convenience constant for when no permissions are granted. */
export const NO_PERMISSIONS: PermissionCapabilities = {
  userRead: false,
  userDisable: false,
  employeeManage: false,
  employeeOffboard: false,
  departmentManage: false,
  applicationRead: false,
  applicationManage: false,
  applicationSecretRotate: false,
  policyRead: false,
  policyManage: false,
  policyPublish: false,
  auditRead: false,
  auditExport: false,
  providerRead: false,
  providerManage: false,
} as const;

/** Convenience constant for when all permissions are granted (mock admin). */
export const FULL_PERMISSIONS: PermissionCapabilities = {
  userRead: true,
  userDisable: true,
  employeeManage: true,
  employeeOffboard: true,
  departmentManage: true,
  applicationRead: true,
  applicationManage: true,
  applicationSecretRotate: true,
  policyRead: true,
  policyManage: true,
  policyPublish: true,
  auditRead: true,
  auditExport: true,
  providerRead: true,
  providerManage: true,
} as const;
