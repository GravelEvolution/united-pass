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

/**
 * MVP 同意模式。`trusted_first_party` 暂不支持，待后端实现信任策略后再加。
 */
export type ConsentMode =
  | "always"
  | "first_authorization";

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
  ownerId: string;
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

/**
 * ownerId is the stable United Pass user ID of the accountable owner
 * (required by the backend contract); ownerName is server-resolved for display.
 */
export type ApplicationCreateInput = {
  name: string;
  description: string;
  audience: ApplicationAudience;
  ownerId: string;
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
  ownerId?: string;
};

export type ClientProfileConfig = {
  profile: ClientProfile;
  label: string;
  description: string;
  clientType: "public" | "confidential";
  grantTypes: OAuthGrantType[];
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  redirectUriRequired: boolean;
  /**
   * 该 Profile 是否允许选择 `openid` Scope。
   * `server_to_server` 不允许，因为 Client Credentials Grant 无用户参与。
   */
  openidAllowed: boolean;
  /**
   * 该 Profile 是否强制要求 `openid` Scope。
   * MVP 中所有 Profile 均为 `false`，由管理员按需选择。
   */
  openidRequired: boolean;
  consentApplicable: boolean;
  /**
   * 该 Profile 当前是否被后端提供方拒绝。非空时表示暂不支持的原因，
   * 创建表单会禁用该选项；枚举本身保留以兼容历史记录。
   */
  unsupportedReason?: string;
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
    openidRequired: false,
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
    openidRequired: false,
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
    openidRequired: false,
    consentApplicable: false,
    unsupportedReason: "ZITADEL v2.71 暂不支持",
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
};

export const AUDIENCE_LABELS: Record<ApplicationAudience, string> = {
  internal: "内部应用",
  external: "外部应用",
  hybrid: "混合应用",
};
