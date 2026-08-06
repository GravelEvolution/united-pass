"use client";

import { type FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Button,
  Checkbox,
  Input,
  Radio,
  RadioGroup,
  Select,
  TextArea,
  Toast,
} from "@douyinfe/semi-ui";
import {
  IconPlus,
  IconMinus,
  IconCopy,
} from "@douyinfe/semi-icons";
import {
  AUDIENCE_LABELS,
  CLIENT_PROFILES,
  CONSENT_MODE_LABELS,
  getClientProfileConfig,
  type AllowedScope,
  type ApplicationAudience,
  type ClientProfile,
  type ConsentMode,
  type ApplicationWithInitialClientResult,
} from "@/features/applications/types";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { PageHeader } from "@/components/common/page-header";
import styles from "./application-create-form.module.css";

type ApplicationCreateFormProps = {
  availableScopes: AllowedScope[];
};

const audienceOptions: Array<{ value: ApplicationAudience; description: string }> = [
  { value: "internal", description: "仅组织内部使用，不对外发布。" },
  { value: "external", description: "面向所有用户开放授权。" },
  { value: "hybrid", description: "同时支持内部和外部使用场景。" },
];

const consentModeOrder: ConsentMode[] = [
  "always",
  "first_authorization",
];

function isApplicationAudience(value: unknown): value is ApplicationAudience {
  return value === "internal" || value === "external" || value === "hybrid";
}

function isClientProfile(value: unknown): value is ClientProfile {
  return value === "web_server" || value === "spa_mobile" || value === "server_to_server";
}

function isConsentMode(value: unknown): value is ConsentMode {
  return value === "always" || value === "first_authorization";
}

export function ApplicationCreateForm({ availableScopes }: ApplicationCreateFormProps) {
  const router = useRouter();

  const [step, setStep] = useState<1 | 2>(1);

  // Step 1 - application info
  const [appName, setAppName] = useState("");
  const [appDescription, setAppDescription] = useState("");
  const [audience, setAudience] = useState<ApplicationAudience>("internal");
  const [ownerId, setOwnerId] = useState("");

  // Step 2 - first client
  const [clientName, setClientName] = useState("");
  const [profile, setProfile] = useState<ClientProfile>("web_server");
  const [redirectUris, setRedirectUris] = useState<string[]>([""]);
  const [logoutUri, setLogoutUri] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<string[]>(["openid"]);
  const [consentMode, setConsentMode] = useState<ConsentMode>("always");

  // results
  const [creationResult, setCreationResult] = useState<ApplicationWithInitialClientResult>();

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string>();

  const profileConfig = getClientProfileConfig(profile);
  const openidForced = profileConfig.openidRequired;
  const hasUserInteraction = profile !== "server_to_server";

  // openid is forced when required by the profile; unavailable for server-to-server;
  // optional (admin's choice) when allowed but not required.
  const effectiveScopes = openidForced
    ? selectedScopes.includes("openid")
      ? selectedScopes
      : [...selectedScopes, "openid"]
    : profileConfig.openidAllowed
      ? selectedScopes
      : selectedScopes.filter((scope) => scope !== "openid");

  const consentModeOptions = consentModeOrder;

  function addRedirectUri() {
    setRedirectUris((uris) => [...uris, ""]);
  }

  function removeRedirectUri(index: number) {
    setRedirectUris((uris) => uris.filter((_, uriIndex) => uriIndex !== index));
  }

  function updateRedirectUri(index: number, value: string) {
    setRedirectUris((uris) => uris.map((uri, uriIndex) => (uriIndex === index ? value : uri)));
  }

  function toggleScope(scope: string) {
    setSelectedScopes((scopes) =>
      scopes.includes(scope)
        ? scopes.filter((storedScope) => storedScope !== scope)
        : [...scopes, scope],
    );
  }

  function handleStepOneSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(undefined);

    if (appName.trim().length < 2) {
      setFormError("应用名称至少需要 2 个字符。");
      return;
    }

    if (ownerId.trim().length === 0) {
      setFormError("请填写负责人 User ID。");
      return;
    }

    setStep(2);
  }

  async function handleStepTwoSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(undefined);

    if (appName.trim().length < 2) {
      setFormError("应用名称至少需要 2 个字符。");
      return;
    }

    if (ownerId.trim().length === 0) {
      setFormError("请填写负责人 User ID。");
      return;
    }

    if (clientName.trim().length < 2) {
      setFormError("客户端名称至少需要 2 个字符。");
      return;
    }

    let validRedirectUris: string[] = [];
    if (hasUserInteraction) {
      validRedirectUris = redirectUris
        .map((uri) => uri.trim())
        .filter((uri) => uri.length > 0);
      if (validRedirectUris.length === 0) {
        setFormError("至少需要填写一个 Redirect URI。");
        return;
      }
    }

    setIsSubmitting(true);
    try {
      const result = await browserCommands.createApplicationWithInitialClient({
        application: {
          name: appName.trim(),
          description: appDescription.trim(),
          audience,
          ownerId: ownerId.trim(),
        },
        initialClient: {
          name: clientName.trim(),
          profile,
          redirectUris: validRedirectUris,
          logoutUri: hasUserInteraction ? logoutUri.trim() : "",
          allowedScopes: effectiveScopes,
          consentMode: hasUserInteraction ? consentMode : "always",
        },
      });
      setCreationResult(result);
      Toast.success({ content: "应用与客户端已创建。" });
    } catch {
      setFormError("创建失败，请重试。");
    } finally {
      setIsSubmitting(false);
    }
  }

  async function copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      Toast.success({ content: "已复制到剪贴板。" });
    } catch {
      Toast.error({ content: "复制失败，请手动选择并复制。" });
    }
  }

  if (creationResult) {
    const clientSecret = creationResult.clientSecret;
    return (
      <>
        <PageHeader
          eyebrow="OAuth 2.0 / OIDC"
          title="应用与客户端已创建"
          description="请安全保存以下凭据。Client Secret 仅在创建时展示一次。"
        />
        <div className={styles.resultPanel}>
          <div className={styles.resultHeader}>
            <span className={styles.mockBadge}>MOCK</span>
            <h2>创建结果</h2>
          </div>

          <div className={styles.resultField}>
            <span>Application ID</span>
            <code>{creationResult.applicationId}</code>
          </div>

          <div className={styles.resultField}>
            <span>Client ID</span>
            <div className={styles.redirectRow}>
              <code>{creationResult.clientId}</code>
              <Button
                size="small"
                theme="borderless"
                icon={<IconCopy />}
                aria-label="复制 Client ID"
                onClick={() => copyToClipboard(creationResult.clientId)}
              />
            </div>
          </div>

          {clientSecret !== undefined ? (
            <>
              <div className={styles.resultField}>
                <span>Client Secret（仅此一次展示）</span>
                <div className={styles.redirectRow}>
                  <code>{clientSecret}</code>
                  <Button
                    size="small"
                    theme="borderless"
                    icon={<IconCopy />}
                    aria-label="复制 Client Secret"
                    onClick={() => copyToClipboard(clientSecret)}
                  />
                </div>
              </div>
              <div className={styles.secretWarning}>
                <strong>此密钥不会再次显示</strong>
                离开此页面后无法重新查看 Client Secret。请立即复制并安全存储。如需轮换密钥，请在应用详情页操作。
              </div>
            </>
          ) : (
            <div className={`${styles.notice} ${styles.noticeInfo}`}>
              <strong>公共客户端不生成 Client Secret</strong>
              此应用使用 Authorization Code + PKCE 流程。客户端密钥不会存储或展示。
            </div>
          )}

          <div className={styles.resultActions}>
            <Link href={`/admin/applications/${creationResult.applicationId}`}>
              <Button type="primary" theme="solid">查看应用详情</Button>
            </Link>
            <Button theme="outline" onClick={() => router.push("/admin/applications")}>
              返回应用列表
            </Button>
          </div>
        </div>
      </>
    );
  }

  if (step === 1) {
    return (
      <>
        <PageHeader
          eyebrow="OAuth 2.0 / OIDC"
          title="注册 OAuth 应用"
          description="第一步：填写应用基本信息。创建后再配置首个客户端。"
        />

        <form className={styles.form} onSubmit={handleStepOneSubmit}>
          <div className={styles.fieldGroup}>
            <label>
              <span className={styles.fieldLabel}>应用名称</span>
              <Input
                value={appName}
                onChange={(value) => setAppName(value)}
                size="large"
                placeholder="例如 United Workspace"
                required
                minLength={2}
                maxLength={64}
              />
              <small className={styles.fieldHint}>用户在授权确认页看到的应用名称。</small>
            </label>
          </div>

          <div className={styles.fieldGroup}>
            <label>
              <span className={styles.fieldLabel}>应用说明</span>
              <TextArea
                value={appDescription}
                onChange={(value) => setAppDescription(value)}
                placeholder="简要描述应用用途"
                rows={3}
                maxCount={280}
              />
            </label>
          </div>

          <div className={styles.fieldGroup}>
            <span className={styles.fieldLabel}>应用受众</span>
            <small className={styles.fieldHint}>决定可用客户端配置与授权策略范围。</small>
            <RadioGroup
              value={audience}
              onChange={(event) => {
                if (isApplicationAudience(event.target.value)) {
                  setAudience(event.target.value);
                }
              }}
              direction="vertical"
            >
              {audienceOptions.map((option) => (
                <Radio key={option.value} value={option.value}>
                  {AUDIENCE_LABELS[option.value]}
                  <span className={styles.fieldHint} style={{ marginLeft: 8 }}>{option.description}</span>
                </Radio>
              ))}
            </RadioGroup>
          </div>

          <div className={styles.fieldGroup}>
            <label>
              <span className={styles.fieldLabel}>负责人 User ID</span>
              <Input
                value={ownerId}
                onChange={(value) => setOwnerId(value)}
                placeholder="例如 usr_01JUP8M8B4Q7R4T6PK1D"
                required
              />
              <small className={styles.fieldHint}>应用管理责任人的稳定用户 ID，后端据此解析显示名称。</small>
            </label>
          </div>

          {formError && (
            <div className={`${styles.notice} ${styles.noticeDanger}`} role="alert">
              {formError}
            </div>
          )}

          <div className={styles.actions}>
            <Button htmlType="submit" type="primary" theme="solid" size="large">
            继续配置客户端
          </Button>
            <Link href="/admin/applications">
              <Button size="large" theme="outline">取消</Button>
            </Link>
          </div>
        </form>
      </>
    );
  }

  return (
    <>
      <PageHeader
        eyebrow="OAuth 2.0 / OIDC"
        title="配置首个客户端"
        description={`第二步：为应用「${appName}」创建第一个 OAuth 客户端。`}
      />

      <form className={styles.form} onSubmit={handleStepTwoSubmit}>
        <div className={styles.fieldGroup}>
          <label>
            <span className={styles.fieldLabel}>客户端名称</span>
            <Input
              value={clientName}
              onChange={(value) => setClientName(value)}
              size="large"
              placeholder="例如 Web 端"
              required
              minLength={2}
              maxLength={64}
            />
            <small className={styles.fieldHint}>用于在管理界面区分同一应用的多个客户端。</small>
          </label>
        </div>

        <div className={styles.fieldGroup}>
          <span className={styles.fieldLabel}>客户端 Profile</span>
          <small className={styles.fieldHint}>Profile 决定授权类型、令牌端点认证方式与是否生成密钥。</small>
          <RadioGroup
            value={profile}
            onChange={(event) => {
              if (isClientProfile(event.target.value) && !getClientProfileConfig(event.target.value).unsupportedReason) {
                setProfile(event.target.value);
              }
            }}
            direction="vertical"
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
        </div>

        {hasUserInteraction && (
          <div className={styles.fieldGroup}>
            <span className={styles.fieldLabel}>Redirect URI</span>
            <small className={styles.fieldHint}>至少填写一个。后端将按精确安全语义校验，前端不会静默归一化。</small>
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
                      onClick={() => removeRedirectUri(index)}
                    />
                  )}
                </div>
              ))}
            </div>
            <Button
              theme="light"
              icon={<IconPlus />}
              onClick={addRedirectUri}
              size="small"
            >
              添加 Redirect URI
            </Button>
          </div>
        )}

        {hasUserInteraction && (
          <div className={styles.fieldGroup}>
            <label>
              <span className={styles.fieldLabel}>Logout URI（可选）</span>
              <Input
                value={logoutUri}
                onChange={(value) => setLogoutUri(value)}
                placeholder="https://your-app.example/auth/logout"
              />
              <small className={styles.fieldHint}>用户登出时的跳转地址。</small>
            </label>
          </div>
        )}

        <div className={styles.fieldGroup}>
          <span className={styles.fieldLabel}>允许申请的 Scope</span>
          <small className={styles.fieldHint}>
            {openidForced
              ? "OpenID 在当前 Profile 下为必选项。"
              : profileConfig.openidAllowed
                ? "OpenID 为可选项，按需勾选。"
                : "当前 Profile 为机器对机器通信，不支持 OpenID。"}
          </small>
          <div className={styles.scopeList}>
            {availableScopes.map((scopeOption) => {
              const isOpenid = scopeOption.scope === "openid";
              const openidDisabled = isOpenid && !profileConfig.openidAllowed;
              const openidChecked = isOpenid
                ? openidForced || (profileConfig.openidAllowed && selectedScopes.includes("openid"))
                : effectiveScopes.includes(scopeOption.scope);
              const disabled = isOpenid ? openidForced || openidDisabled : false;
              return (
                <div key={scopeOption.scope} className={styles.scopeItem}>
                  <Checkbox
                    checked={openidChecked}
                    disabled={disabled}
                    onChange={() => toggleScope(scopeOption.scope)}
                    aria-label={scopeOption.label}
                  >
                    <div>
                      <strong>{scopeOption.label}</strong>
                      {isOpenid && openidForced && (
                        <span className={styles.fieldHint} style={{ marginLeft: 6 }}>（必选）</span>
                      )}
                      {isOpenid && !openidForced && profileConfig.openidAllowed && (
                        <span className={styles.fieldHint} style={{ marginLeft: 6 }}>（可选）</span>
                      )}
                      <p>
                        <code>{scopeOption.scope}</code> — {scopeOption.description}
                      </p>
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
                onChange={(value) => {
                  if (isConsentMode(value)) {
                    setConsentMode(value);
                  }
                }}
                style={{ width: "100%" }}
              >
                {consentModeOptions.map((mode) => (
                  <Select.Option key={mode} value={mode}>
                    {CONSENT_MODE_LABELS[mode]}
                  </Select.Option>
                ))}
              </Select>
              <small className={styles.fieldHint}>
                选择每次授权都确认，或仅首次授权确认。跳过确认模式将在后端实现信任策略后开放。
              </small>
            </label>
          </div>
        )}

        {formError && (
          <div className={`${styles.notice} ${styles.noticeDanger}`} role="alert">
            {formError}
          </div>
        )}

        <div className={styles.actions}>
          <Button htmlType="submit" type="primary" theme="solid" size="large" loading={isSubmitting}>
            创建客户端（Mock）
          </Button>
          <Button
            size="large"
            theme="outline"
            onClick={() => setStep(1)}
            disabled={isSubmitting}
          >
            返回上一步
          </Button>
          <Link href="/admin/applications">
            <Button size="large" theme="outline">取消</Button>
          </Link>
        </div>
      </form>
    </>
  );
}
