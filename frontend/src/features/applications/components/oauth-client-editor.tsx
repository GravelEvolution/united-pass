//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Shared create/edit form for OAuth clients
//

"use client";

import type { FormEvent } from "react";
import { useMemo, useState } from "react";
import { Button, Checkbox, Input, Radio, RadioGroup, Select, Toast } from "@douyinfe/semi-ui";
import { IconMinus, IconPlus, IconTick } from "@douyinfe/semi-icons";
import {
  CLIENT_PROFILES,
  CONSENT_MODE_LABELS,
  getClientProfileConfig,
  inferClientProfile,
  type AllowedScope,
  type ApplicationAudience,
  type ClientProfile,
  type ConsentMode,
  type OAuthClient,
  type OAuthClientCreationResult,
} from "@/features/applications/types";
import {
  ApplicationValidationError,
  validateConsentModeWithAudience,
  validateOAuthClientCreateInput,
} from "@/features/applications/validation";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import styles from "./application-create-form.module.css";

type OAuthClientEditorProps = {
  applicationId: string;
  applicationAudience: ApplicationAudience;
  availableScopes: AllowedScope[];
  client?: OAuthClient;
  onDone: (clientId: string) => void;
  onCancel: () => void;
};

function isClientProfile(value: unknown): value is ClientProfile {
  return value === "web_server" || value === "spa_mobile" || value === "server_to_server";
}

function isConsentMode(value: unknown): value is ConsentMode {
  return value === "always" || value === "first_authorization";
}

export function OAuthClientEditor({
  applicationId,
  applicationAudience,
  availableScopes,
  client,
  onDone,
  onCancel,
}: OAuthClientEditorProps) {
  const editing = client !== undefined;
  const initialProfile = client ? inferClientProfile(client) : "web_server";
  const [name, setName] = useState(client?.name ?? "");
  const [profile, setProfile] = useState<ClientProfile>(initialProfile);
  const [redirectUris, setRedirectUris] = useState<string[]>(
    client ? client.redirectUris.map((entry) => entry.uri) : [""],
  );
  const [logoutUri, setLogoutUri] = useState(client?.logoutUri ?? "");
  const [selectedScopes, setSelectedScopes] = useState<string[]>(
    client ? client.allowedScopes.map((scope) => scope.scope) : ["openid", "profile", "email"],
  );
  const [consentMode, setConsentMode] = useState<ConsentMode>(client?.consentMode ?? "always");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string>();
  const [creationResult, setCreationResult] = useState<OAuthClientCreationResult>();

  const profileConfig = getClientProfileConfig(profile);
  const hasUserInteraction = profileConfig.consentApplicable;
  const effectiveScopes = useMemo(() => {
    const next = selectedScopes.filter((scope) => scope !== "openid" || profileConfig.openidAllowed);
    for (const scope of availableScopes) {
      if (scope.required && !next.includes(scope.scope)) next.push(scope.scope);
    }
    if (profileConfig.openidRequired && !next.includes("openid")) next.push("openid");
    return next;
  }, [availableScopes, profileConfig, selectedScopes]);

  function changeProfile(nextProfile: ClientProfile): void {
    const nextConfig = getClientProfileConfig(nextProfile);
    setProfile(nextProfile);
    if (!nextConfig.redirectUriRequired) setRedirectUris([]);
    else if (redirectUris.length === 0) setRedirectUris([""]);
    if (!nextConfig.openidAllowed) {
      setSelectedScopes((scopes) => scopes.filter((scope) => scope !== "openid"));
    }
    if (!nextConfig.consentApplicable) setConsentMode("always");
    setFormError(undefined);
  }

  function updateRedirectUri(index: number, value: string): void {
    setRedirectUris((uris) => uris.map((uri, uriIndex) => uriIndex === index ? value : uri));
  }

  function toggleScope(scope: string): void {
    setSelectedScopes((scopes) => scopes.includes(scope)
      ? scopes.filter((item) => item !== scope)
      : [...scopes, scope]);
  }

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setFormError(undefined);
    const normalizedRedirectUris = profileConfig.redirectUriRequired
      ? redirectUris.map((uri) => uri.trim()).filter(Boolean)
      : [];
    const normalizedLogoutUri = profileConfig.redirectUriRequired ? logoutUri.trim() : "";
    const normalizedConsentMode = profileConfig.consentApplicable ? consentMode : "always";
    const normalizedName = name.trim();

    try {
      validateOAuthClientCreateInput({
        applicationId,
        name: normalizedName,
        profile,
        redirectUris: normalizedRedirectUris,
        logoutUri: normalizedLogoutUri,
        allowedScopes: effectiveScopes,
        consentMode: normalizedConsentMode,
      });
      validateConsentModeWithAudience(normalizedConsentMode, applicationAudience, profileConfig);
    } catch (error) {
      setFormError(error instanceof ApplicationValidationError ? error.message : "客户端配置无效。");
      return;
    }

    setSubmitting(true);
    try {
      if (client) {
        await browserCommands.updateOAuthClient(applicationId, client.clientId, {
          name: normalizedName,
          redirectUris: normalizedRedirectUris,
          logoutUri: normalizedLogoutUri,
          allowedScopes: effectiveScopes,
          consentMode: normalizedConsentMode,
        });
        Toast.success({ content: "OAuth Client 配置已更新。" });
        onDone(client.clientId);
        return;
      }

      const result = await browserCommands.createOAuthClient({
        applicationId,
        name: normalizedName,
        profile,
        redirectUris: normalizedRedirectUris,
        logoutUri: normalizedLogoutUri,
        allowedScopes: effectiveScopes,
        consentMode: normalizedConsentMode,
      });
      setCreationResult(result);
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "保存 OAuth Client 失败，请重试。");
    } finally {
      setSubmitting(false);
    }
  }

  async function copySecret(secret: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(secret);
      Toast.success({ content: "Client Secret 已复制。" });
    } catch {
      Toast.error({ content: "复制失败，请手动选择并复制。" });
    }
  }

  if (creationResult) {
    return (
      <div className={styles.resultPanel} role="status">
        <div className={styles.resultHeader}>
          <IconTick size="extra-large" style={{ color: "var(--up-success)" }} />
          <h2>OAuth Client 已创建</h2>
        </div>
        <div className={styles.resultField}>
          <span>Client ID</span>
          <code>{creationResult.clientId}</code>
        </div>
        {creationResult.clientSecret && (
          <div className={styles.secretWarning}>
            <strong>Client Secret 仅此一次展示</strong>
            <code>{creationResult.clientSecret}</code>
            <Button size="small" theme="borderless" onClick={() => void copySecret(creationResult.clientSecret!)}>
              复制 Secret
            </Button>
            <p>关闭前请保存到受控的 Secret Manager；页面不会写入本地存储。</p>
          </div>
        )}
        <div className={styles.resultActions}>
          <Button type="primary" theme="solid" onClick={() => onDone(creationResult.clientId)}>
            {creationResult.clientSecret ? "我已安全保存，完成" : "完成"}
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form className={styles.form} onSubmit={(event) => void submit(event)}>
      <div className={styles.fieldGroup}>
        <label>
          <span className={styles.fieldLabel}>客户端名称</span>
          <Input value={name} onChange={setName} minLength={2} maxLength={64} required />
        </label>
      </div>

      <div className={styles.fieldGroup}>
        <span className={styles.fieldLabel}>客户端 Profile</span>
        {editing ? (
          <small className={styles.fieldHint}>
            {profileConfig.label}。Profile 创建后不可修改。
          </small>
        ) : (
          <RadioGroup
            value={profile}
            direction="vertical"
            onChange={(event) => {
              if (isClientProfile(event.target.value)) changeProfile(event.target.value);
            }}
          >
            {CLIENT_PROFILES.map((config) => (
              <Radio key={config.profile} value={config.profile} disabled={Boolean(config.unsupportedReason)}>
                {config.label}
                <span className={styles.fieldHint} style={{ marginLeft: 8 }}>
                  {config.unsupportedReason ? `${config.description}（${config.unsupportedReason}）` : config.description}
                </span>
              </Radio>
            ))}
          </RadioGroup>
        )}
      </div>

      {profileConfig.redirectUriRequired && (
        <div className={styles.fieldGroup}>
          <span className={styles.fieldLabel}>Redirect URI</span>
          <small className={styles.fieldHint}>整组保存；仅接受 HTTPS 或本地回环 HTTP 地址，不做静默归一化。</small>
          <div className={styles.redirectList}>
            {redirectUris.map((uri, index) => (
              <div key={index} className={styles.redirectRow}>
                <Input
                  value={uri}
                  onChange={(value) => updateRedirectUri(index, value)}
                  placeholder="https://your-app.example/auth/callback"
                  aria-label={`Redirect URI ${index + 1}`}
                />
                {redirectUris.length > 1 && (
                  <Button
                    theme="borderless"
                    icon={<IconMinus />}
                    aria-label="删除此 Redirect URI"
                    onClick={() => setRedirectUris((uris) => uris.filter((_, uriIndex) => uriIndex !== index))}
                  />
                )}
              </div>
            ))}
          </div>
          <Button
            theme="light"
            size="small"
            icon={<IconPlus />}
            disabled={redirectUris.length >= 20}
            onClick={() => setRedirectUris((uris) => [...uris, ""])}
          >
            添加 Redirect URI
          </Button>
        </div>
      )}

      {profileConfig.redirectUriRequired && (
        <div className={styles.fieldGroup}>
          <label>
            <span className={styles.fieldLabel}>Logout URI（可选）</span>
            <Input value={logoutUri} onChange={setLogoutUri} placeholder="https://your-app.example/auth/logout" />
            <small className={styles.fieldHint}>留空会向后端发送空字符串并清除现有配置。</small>
          </label>
        </div>
      )}

      <div className={styles.fieldGroup}>
        <span className={styles.fieldLabel}>允许申请的 Scope</span>
        <div className={styles.scopeList}>
          {availableScopes.map((scope) => {
            const disabled = scope.required
              || (scope.scope === "openid" && (!profileConfig.openidAllowed || profileConfig.openidRequired));
            const checked = effectiveScopes.includes(scope.scope);
            return (
              <div key={scope.scope} className={styles.scopeItem}>
                <Checkbox
                  checked={checked}
                  disabled={disabled}
                  onChange={() => toggleScope(scope.scope)}
                  aria-label={scope.label}
                >
                  <div>
                    <strong>{scope.label}{scope.required && "（必选）"}</strong>
                    <p><code>{scope.scope}</code> — {scope.description}</p>
                  </div>
                </Checkbox>
              </div>
            );
          })}
        </div>
      </div>

      {hasUserInteraction && (
        <div className={styles.fieldGroup}>
          <label>
            <span className={styles.fieldLabel}>授权确认模式</span>
            <Select
              value={consentMode}
              style={{ width: "100%" }}
              onChange={(value) => {
                if (isConsentMode(value)) setConsentMode(value);
              }}
            >
              {(Object.keys(CONSENT_MODE_LABELS) as ConsentMode[]).map((mode) => (
                <Select.Option key={mode} value={mode}>{CONSENT_MODE_LABELS[mode]}</Select.Option>
              ))}
            </Select>
          </label>
        </div>
      )}

      {formError && <div className={`${styles.notice} ${styles.noticeDanger}`} role="alert">{formError}</div>}

      <div className={styles.actions}>
        <Button htmlType="submit" type="primary" theme="solid" loading={submitting} disabled={submitting}>
          {editing ? "保存 Client 配置" : "创建 OAuth Client"}
        </Button>
        <Button theme="outline" onClick={onCancel} disabled={submitting}>取消</Button>
      </div>
    </form>
  );
}
