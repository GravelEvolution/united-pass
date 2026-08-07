//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Client-side validation for the application and client forms
//

import type {
  ApplicationAudience,
  ApplicationCreateInput,
  ClientProfile,
  ClientProfileConfig,
  ConsentMode,
  OAuthClientCreateInput,
} from "./types";
import { getClientProfileConfig } from "./types";

/**
 * Domain validation for application and OAuth client creation.
 *
 * These pure functions encode the invariant rules that both the mock data
 * source and the future real HTTP-backed API layer must enforce. They throw
 * on validation failure so callers can surface a user-facing error.
 */

export class ApplicationValidationError extends Error {
  readonly field: string;

  constructor(field: string, message: string) {
    super(message);
    this.name = "ApplicationValidationError";
    this.field = field;
  }
}

// --- Application ---

export function validateApplicationCreateInput(input: ApplicationCreateInput): void {
  if (input.name.trim().length < 2) {
    throw new ApplicationValidationError("name", "应用名称至少需要 2 个字符。");
  }
  if (input.name.trim().length > 80) {
    throw new ApplicationValidationError("name", "应用名称不能超过 80 个字符。");
  }
  if (input.ownerId.trim().length === 0) {
    throw new ApplicationValidationError("ownerId", "请填写负责人 User ID。");
  }
  if (!isValidAudience(input.audience)) {
    throw new ApplicationValidationError("audience", `未知的应用受众类型: ${input.audience}`);
  }
}

// --- OAuth Client ---

export function validateOAuthClientCreateInput(input: OAuthClientCreateInput): void {
  if (input.name.trim().length < 2) {
    throw new ApplicationValidationError("name", "客户端名称至少需要 2 个字符。");
  }
  if (input.name.trim().length > 64) {
    throw new ApplicationValidationError("name", "客户端名称不能超过 64 个字符。");
  }

  const profileConfig = getClientProfileConfig(input.profile);

  validateRedirectUris(input.redirectUris, profileConfig);
  validateRequestedScopes(input.allowedScopes, profileConfig);
  validateConsentMode(input.consentMode, profileConfig);
}

export function validateClientProfileConstraints(
  profile: ClientProfile,
  scopes: string[],
  redirectUris: string[],
): void {
  const profileConfig = getClientProfileConfig(profile);

  if (!profileConfig.openidAllowed && scopes.includes("openid")) {
    throw new ApplicationValidationError(
      "allowedScopes",
      `${profileConfig.label} Profile 不支持 openid Scope。openid 仅适用于需要用户交互的客户端。`,
    );
  }

  if (profileConfig.openidRequired && !scopes.includes("openid")) {
    throw new ApplicationValidationError(
      "allowedScopes",
      `${profileConfig.label} Profile 必须包含 openid Scope。`,
    );
  }

  if (profileConfig.redirectUriRequired && redirectUris.length === 0) {
    throw new ApplicationValidationError(
      "redirectUris",
      `${profileConfig.label} Profile 至少需要一个 Redirect URI。`,
    );
  }

  if (!profileConfig.redirectUriRequired && redirectUris.length > 0) {
    throw new ApplicationValidationError(
      "redirectUris",
      `${profileConfig.label} Profile 不需要 Redirect URI。`,
    );
  }
}

export function validateConsentMode(
  consentMode: ConsentMode,
  profileConfig: ClientProfileConfig,
): void {
  if (!isValidConsentMode(consentMode)) {
    throw new ApplicationValidationError("consentMode", `未知的同意模式: ${consentMode}`);
  }

  if (!profileConfig.consentApplicable && consentMode !== "always") {
    throw new ApplicationValidationError(
      "consentMode",
      `${profileConfig.label} Profile 无用户交互，同意模式必须为 always。`,
    );
  }
}

export function validateConsentModeWithAudience(
  consentMode: ConsentMode,
  _audience: ApplicationAudience,
  profileConfig: ClientProfileConfig,
): void {
  validateConsentMode(consentMode, profileConfig);

  // `trusted_first_party` was removed from MVP; when the backend implements
  // trust policies, re-add it here with audience + permission checks.
}

export function validateRequestedScopes(
  requestedScopes: string[],
  profileConfig: ClientProfileConfig,
): void {
  const knownScopes = new Set(availableScopeIds());
  const unknown = requestedScopes.filter((scope) => !knownScopes.has(scope));

  if (unknown.length > 0) {
    throw new ApplicationValidationError(
      "allowedScopes",
      `未知的 Scope: ${unknown.join(", ")}。请使用已登记的 Scope。`,
    );
  }

  if (!profileConfig.openidAllowed && requestedScopes.includes("openid")) {
    throw new ApplicationValidationError(
      "allowedScopes",
      `${profileConfig.label} Profile 不支持 openid Scope。`,
    );
  }

  if (profileConfig.openidRequired && !requestedScopes.includes("openid")) {
    throw new ApplicationValidationError(
      "allowedScopes",
      `${profileConfig.label} Profile 必须包含 openid Scope。`,
    );
  }
}

export function validateRedirectUris(
  uris: string[],
  profileConfig: ClientProfileConfig,
): void {
  if (!profileConfig.redirectUriRequired && uris.length > 0) {
    throw new ApplicationValidationError(
      "redirectUris",
      `${profileConfig.label} Profile 不需要 Redirect URI。`,
    );
  }

  for (const uri of uris) {
    if (!isValidRedirectUri(uri)) {
      throw new ApplicationValidationError(
        "redirectUris",
        `Redirect URI 格式无效: ${uri}。仅接受 https:// 或本地回环 http:// 地址。`,
      );
    }
  }
}

// --- Internals ---

const KNOWN_SCOPE_IDS = [
  "openid",
  "profile",
  "email",
  "phone",
  "offline_access",
  "reporting:read",
] as const;

function availableScopeIds(): readonly string[] {
  return KNOWN_SCOPE_IDS;
}

function isValidAudience(audience: string): boolean {
  return audience === "internal" || audience === "external" || audience === "hybrid";
}

function isValidConsentMode(mode: string): boolean {
  return mode === "always" || mode === "first_authorization";
}

function isValidRedirectUri(uri: string): boolean {
  if (typeof uri !== "string" || uri.trim().length === 0) {
    return false;
  }

  try {
    const parsed = new URL(uri);
    if (parsed.protocol === "https:") {
      return true;
    }
    if (parsed.protocol === "http:") {
      const hostname = parsed.hostname;
      return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
    }
    return false;
  } catch {
    return false;
  }
}
