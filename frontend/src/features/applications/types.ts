export type ApplicationAudience = "internal" | "external" | "hybrid";

export type ApplicationStatus = "active" | "disabled";

export type OAuthGrantType =
  | "authorization_code"
  | "refresh_token"
  | "client_credentials";

export type TokenEndpointAuthMethod =
  | "client_secret_post"
  | "client_secret_basic"
  | "none"
  | "private_key_jwt";

export type ClientProfile =
  | "web_server"
  | "spa_mobile"
  | "server_to_server";

export type ConsentMode =
  | "always"
  | "first_authorization"
  | "trusted_first_party";

export type RedirectUriEntry = {
  uri: string;
  isLoopback: boolean;
  addedAt: string;
};

export type AllowedScope = {
  scope: string;
  label: string;
  description: string;
  required: boolean;
};

export type ClientSecretRecord = {
  secretId: string;
  label: string;
  createdAt: string;
  lastRotatedAt: string | null;
};

export type ApplicationGrantSummary = {
  grantId: string;
  userLabel: string;
  scopes: string[];
  grantedAt: string;
  lastUsedAt: string | null;
  status: "active" | "revoked";
};

export type ApplicationAuditEntry = {
  eventId: string;
  eventType: string;
  actorName: string;
  occurredAt: string;
  result: "success" | "denied";
};

export type OAuthApplication = {
  applicationId: string;
  name: string;
  audience: ApplicationAudience;
  ownerName: string;
  status: ApplicationStatus;
  clientCount: number;
  updatedAt: string;
};

export type OAuthClient = {
  clientId: string;
  applicationId: string;
  name: string;
  clientType: "public" | "confidential";
  grantTypes: OAuthGrantType[];
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  redirectUris: RedirectUriEntry[];
  logoutUri: string | null;
  allowedScopes: AllowedScope[];
  consentMode: ConsentMode;
  status: ApplicationStatus;
  clientSecrets: ClientSecretRecord[];
  createdAt: string;
  updatedAt: string;
};

export type OAuthApplicationDetail = {
  applicationId: string;
  name: string;
  description: string;
  logoUrl: string | null;
  audience: ApplicationAudience;
  ownerId: string;
  ownerName: string;
  status: ApplicationStatus;
  clients: OAuthClient[];
  grants: ApplicationGrantSummary[];
  auditEntries: ApplicationAuditEntry[];
  createdAt: string;
  updatedAt: string;
};

export type ApplicationCreateInput = {
  name: string;
  description: string;
  audience: ApplicationAudience;
  ownerName: string;
};

export type OAuthClientCreateInput = {
  applicationId: string;
  name: string;
  profile: ClientProfile;
  redirectUris: string[];
  logoutUri: string;
  allowedScopes: string[];
  consentMode: ConsentMode;
};

export type ApplicationCreationResult = {
  applicationId: string;
};

export type OAuthClientCreationResult = {
  clientId: string;
  clientSecret?: string;
};

export type ApplicationWithInitialClientInput = {
  application: ApplicationCreateInput;
  initialClient: Omit<OAuthClientCreateInput, "applicationId">;
};

export type ApplicationWithInitialClientResult = {
  applicationId: string;
  clientId: string;
  clientSecret?: string;
};

export type SecretRotationResult = {
  secretId: string;
  clientSecret: string;
  previousSecretExpiresAt: string;
};

export type ApplicationUpdateInput = {
  name?: string;
  description?: string;
  audience?: ApplicationAudience;
  ownerName?: string;
};

export type ClientProfileConfig = {
  profile: ClientProfile;
  label: string;
  description: string;
  clientType: "public" | "confidential";
  grantTypes: OAuthGrantType[];
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  redirectUriRequired: boolean;
  openidAllowed: boolean;
  consentApplicable: boolean;
};

export const CLIENT_PROFILES: readonly ClientProfileConfig[] = [
  {
    profile: "web_server",
    label: "Web 服务端",
    description: "服务端渲染或 BFF 架构，可安全存储 Client Secret。",
    clientType: "confidential",
    grantTypes: ["authorization_code", "refresh_token"],
    tokenEndpointAuthMethod: "client_secret_basic",
    redirectUriRequired: true,
    openidAllowed: true,
    consentApplicable: true,
  },
  {
    profile: "spa_mobile",
    label: "SPA / 移动端",
    description: "浏览器或原生应用，使用 PKCE，不存储 Client Secret。",
    clientType: "public",
    grantTypes: ["authorization_code", "refresh_token"],
    tokenEndpointAuthMethod: "none",
    redirectUriRequired: true,
    openidAllowed: true,
    consentApplicable: true,
  },
  {
    profile: "server_to_server",
    label: "服务账号",
    description: "机器对机器通信，使用 Client Credentials Grant，无用户参与。",
    clientType: "confidential",
    grantTypes: ["client_credentials"],
    tokenEndpointAuthMethod: "client_secret_basic",
    redirectUriRequired: false,
    openidAllowed: false,
    consentApplicable: false,
  },
] as const;

export function getClientProfileConfig(profile: ClientProfile): ClientProfileConfig {
  const config = CLIENT_PROFILES.find((item) => item.profile === profile);
  if (!config) {
    throw new Error(`Unknown client profile: ${profile}`);
  }
  return config;
}

export const CONSENT_MODE_LABELS: Record<ConsentMode, string> = {
  always: "每次授权都确认",
  first_authorization: "仅首次授权确认",
  trusted_first_party: "跳过确认（仅内部可信应用）",
};

export const AUDIENCE_LABELS: Record<ApplicationAudience, string> = {
  internal: "内部应用",
  external: "外部应用",
  hybrid: "混合应用",
};
