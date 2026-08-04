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
  TextArea,
  Toast,
} from "@douyinfe/semi-ui";
import {
  IconPlus,
  IconMinus,
  IconCopy,
} from "@douyinfe/semi-icons";
import type { AllowedScope, ApplicationCreationResult, ApplicationKind } from "@/features/applications/types";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";
import { PageHeader } from "@/components/common/page-header";
import styles from "./application-create-form.module.css";

type ApplicationCreateFormProps = {
  availableScopes: AllowedScope[];
};

const applicationKindOptions: Array<{ value: ApplicationKind; label: string; description: string }> = [
  { value: "internal", label: "内部应用", description: "仅组织内部使用，不对外发布。" },
  { value: "public-app", label: "公共应用", description: "面向所有用户开放授权。" },
  { value: "hybrid", label: "混合应用", description: "同时支持内部和外部使用场景。" },
];

export function ApplicationCreateForm({ availableScopes }: ApplicationCreateFormProps) {
  const router = useRouter();
  const [clientType, setClientType] = useState<"public" | "confidential">("confidential");
  const [redirectUris, setRedirectUris] = useState<string[]>([""]);
  const [selectedScopes, setSelectedScopes] = useState<string[]>(["openid"]);
  const [consentRequired, setConsentRequired] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string>();
  const [creationResult, setCreationResult] = useState<ApplicationCreationResult>();

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

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(undefined);

    const formData = new FormData(event.currentTarget);
    const name = formData.get("name");
    const description = formData.get("description");
    const ownerName = formData.get("ownerName");
    const logoutUri = formData.get("logoutUri");
    const kind = formData.get("kind");

    if (typeof name !== "string" || name.trim().length < 2) {
      setFormError("应用名称至少需要 2 个字符。");
      return;
    }

    if (typeof ownerName !== "string" || ownerName.trim().length < 2) {
      setFormError("请填写负责人名称。");
      return;
    }

    const validRedirectUris = redirectUris
      .map((uri) => uri.trim())
      .filter((uri) => uri.length > 0);

    if (validRedirectUris.length === 0) {
      setFormError("至少需要填写一个 Redirect URI。");
      return;
    }

    if (!selectedScopes.includes("openid")) {
      setFormError("OpenID Scope 为必选项。");
      return;
    }

    setIsSubmitting(true);
    try {
      const result = await mockUnitedPassDataSource.createApplication({
        name: name.trim(),
        description: typeof description === "string" ? description.trim() : "",
        kind: (typeof kind === "string" ? kind : "public-app") as ApplicationKind,
        clientType,
        redirectUris: validRedirectUris,
        logoutUri: typeof logoutUri === "string" ? logoutUri.trim() : "",
        allowedScopes: selectedScopes,
        ownerName: ownerName.trim(),
        consentRequired,
      });
      setCreationResult(result);
      Toast.success({ content: "应用注册成功。" });
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
    const showSecret = clientType === "confidential" && clientSecret !== undefined;
    return (
      <>
        <PageHeader
          eyebrow="OAuth 2.0 / OIDC"
          title="应用已创建"
          description="请安全保存以下凭据。Client Secret 仅在创建时展示一次。"
        />
        <div className={styles.resultPanel}>
          <div className={styles.resultHeader}>
            <span className={styles.mockBadge}>MOCK</span>
            <h2>注册结果</h2>
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

          {showSecret && clientSecret !== undefined ? (
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
              此应用必须使用 Authorization Code + PKCE 流程。客户端密钥不会存储或展示。
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

  return (
    <>
      <PageHeader
        eyebrow="OAuth 2.0 / OIDC"
        title="注册 OAuth 应用"
        description="创建应用并配置客户端类型、重定向 URI 和允许的 Scope。"
      />

      <form className={styles.form} onSubmit={handleSubmit}>
        <div className={styles.fieldGroup}>
          <label>
            <span className={styles.fieldLabel}>应用名称</span>
            <Input name="name" size="large" placeholder="例如 United Workspace" required minLength={2} maxLength={64} />
            <small className={styles.fieldHint}>用户在授权确认页看到的应用名称。</small>
          </label>
        </div>

        <div className={styles.fieldGroup}>
          <label>
            <span className={styles.fieldLabel}>应用说明</span>
            <TextArea name="description" placeholder="简要描述应用用途" rows={3} maxCount={280} />
          </label>
        </div>

        <div className={styles.twoColumns}>
          <div className={styles.fieldGroup}>
            <span className={styles.fieldLabel}>应用类型</span>
            <RadioGroup name="kind" defaultValue="public-app" direction="vertical">
              {applicationKindOptions.map((option) => (
                <Radio key={option.value} value={option.value}>
                  {option.label}
                  <span className={styles.fieldHint} style={{ marginLeft: 8 }}>{option.description}</span>
                </Radio>
              ))}
            </RadioGroup>
          </div>

          <div className={styles.fieldGroup}>
            <span className={styles.fieldLabel}>客户端类型</span>
            <RadioGroup
              value={clientType}
              onChange={(event) => setClientType(event.target.value as "public" | "confidential")}
              direction="vertical"
            >
              <Radio value="confidential">
                Confidential（机密客户端）
                <span className={styles.fieldHint} style={{ marginLeft: 8 }}>服务端应用，可安全存储 Client Secret</span>
              </Radio>
              <Radio value="public">
                Public（公共客户端）
                <span className={styles.fieldHint} style={{ marginLeft: 8 }}>SPA、移动端等无法安全存储密钥的应用</span>
              </Radio>
            </RadioGroup>
          </div>
        </div>

        {clientType === "public" ? (
          <div className={`${styles.notice} ${styles.noticeInfo}`}>
            <div>
              <strong>公共客户端安全要求</strong>
              必须使用 Authorization Code + PKCE 流程。不会生成 Client Secret，客户端密钥不会存储或展示。
            </div>
          </div>
        ) : (
          <div className={`${styles.notice} ${styles.noticeWarning}`}>
            <div>
              <strong>机密客户端密钥说明</strong>
              Client Secret 仅在应用创建时展示一次，后续无法再次查看。如需轮换请在应用详情页操作。列表和详情页不会展示密钥明文。
            </div>
          </div>
        )}

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

        <div className={styles.twoColumns}>
          <div className={styles.fieldGroup}>
            <label>
              <span className={styles.fieldLabel}>Logout URI（可选）</span>
              <Input name="logoutUri" placeholder="https://your-app.example/auth/logout" />
              <small className={styles.fieldHint}>用户登出时的跳转地址。</small>
            </label>
          </div>

          <div className={styles.fieldGroup}>
            <label>
              <span className={styles.fieldLabel}>负责人</span>
              <Input name="ownerName" placeholder="例如 协作产品团队" required minLength={2} />
              <small className={styles.fieldHint}>应用管理责任人或团队。</small>
            </label>
          </div>
        </div>

        <div className={styles.fieldGroup}>
          <span className={styles.fieldLabel}>允许申请的 Scope</span>
          <small className={styles.fieldHint}>用户在授权确认页只能看到此处允许的 Scope。</small>
          <div className={styles.scopeList}>
            {availableScopes.map((scopeOption) => (
              <div key={scopeOption.scope} className={styles.scopeItem}>
                <Checkbox
                  checked={selectedScopes.includes(scopeOption.scope)}
                  disabled={scopeOption.required}
                  onChange={() => toggleScope(scopeOption.scope)}
                  aria-label={scopeOption.label}
                >
                  <div>
                    <strong>{scopeOption.label}</strong>
                    {scopeOption.required && <span className={styles.fieldHint} style={{ marginLeft: 6 }}>（必选）</span>}
                    <p>
                      <code>{scopeOption.scope}</code> — {scopeOption.description}
                    </p>
                  </div>
                </Checkbox>
              </div>
            ))}
          </div>
        </div>

        <div className={styles.fieldGroup}>
          <Checkbox
            checked={consentRequired}
            onChange={(event) => setConsentRequired(Boolean(event.target.checked))}
          >
            <span className={styles.fieldLabel}>需要用户确认授权</span>
            <span className={styles.fieldHint} style={{ marginLeft: 8 }}>
              关闭后用户在授权时不显示确认页（仅适用于可信内部应用）。
            </span>
          </Checkbox>
        </div>

        {formError && (
          <div className={`${styles.notice} ${styles.noticeDanger}`} role="alert">
            {formError}
          </div>
        )}

        <div className={styles.actions}>
          <Button htmlType="submit" type="primary" theme="solid" size="large" loading={isSubmitting}>
            创建应用（Mock）
          </Button>
          <Link href="/admin/applications">
            <Button size="large" theme="outline">取消</Button>
          </Link>
        </div>
      </form>
    </>
  );
}
