export type SecurityFactor = {
  factorId: string;
  kind: "password" | "totp" | "passkey";
  label: string;
  status: "active" | "recommended";
  updatedAt?: string;
};

export type UserSession = {
  sessionId: string;
  deviceName: string;
  clientName: string;
  approximateLocation: string;
  ipAddressMasked: string;
  lastActiveAt: string;
  isCurrent: boolean;
};
