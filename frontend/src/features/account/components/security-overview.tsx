"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import { Banner, Button, Input, Modal, Popconfirm, Toast } from "@douyinfe/semi-ui";
import { IconDelete, IconKey, IconShield, IconRefresh, IconLock } from "@douyinfe/semi-icons";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import type { SecurityFactor } from "@/features/account/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import styles from "./account-panels.module.css";

type SecurityOverviewProps = {
  securityFactors: SecurityFactor[];
};

type ActiveModal =
  | { type: "password" }
  | { type: "totp_enroll" }
  | { type: "totp_remove" }
  | { type: "passkey_enroll" }
  | { type: "passkey_remove"; credentialId: string }
  | { type: "recovery_codes" }
  | null;

const PASSWORD_MIN_LENGTH = 12;

const factorDescriptions = {
  password: "用于基础凭据验证，建议定期检查是否存在复用风险。",
  totp: "使用身份验证器生成的一次性动态验证码。",
  passkey: "使用设备生物识别或安全密钥进行抗钓鱼验证。",
} satisfies Record<SecurityFactor["kind"], string>;

export function SecurityOverview({ securityFactors }: SecurityOverviewProps) {
  const [activeModal, setActiveModal] = useState<ActiveModal>(null);
  const [isRevokingSessions, setIsRevokingSessions] = useState(false);
  const [localFactors, setLocalFactors] = useState<SecurityFactor[]>(securityFactors);

  function updateFactorStatus(kind: SecurityFactor["kind"], status: SecurityFactor["status"]): void {
    setLocalFactors((current) =>
      current.map((factor) =>
        factor.kind === kind ? { ...factor, status, updatedAt: new Date().toISOString() } : factor,
      ),
    );
  }

  function removeFactor(kind: SecurityFactor["kind"]): void {
    setLocalFactors((current) => current.filter((factor) => factor.kind !== kind));
  }

  function addFactor(kind: SecurityFactor["kind"], label: string): void {
    setLocalFactors((current) => {
      if (current.some((factor) => factor.kind === kind)) {
        return current.map((factor) =>
          factor.kind === kind
            ? { ...factor, status: "active" as const, updatedAt: new Date().toISOString() }
            : factor,
        );
      }
      return [
        ...current,
        {
          factorId: `factor_${kind}_${Date.now()}`,
          kind,
          label,
          status: "active",
          updatedAt: new Date().toISOString(),
        },
      ];
    });
  }

  async function handleRevokeOtherSessions(): Promise<void> {
    setIsRevokingSessions(true);
    try {
      await browserCommands.revokeOtherSessions();
      Toast.success({ content: "已撤销其他全部会话。" });
    } catch {
      Toast.error({ content: "撤销会话失败，请稍后重试。" });
    } finally {
      setIsRevokingSessions(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Account security"
        title="登录与安全"
        description="管理登录凭据和多重验证方式。重要变更将在后端接入后要求重新验证身份。"
      />
      <section className={styles.card}>
        <div className={styles.cardHeading}>
          <div>
            <span className={styles.label}>AUTHENTICATION</span>
            <h2>验证方式</h2>
          </div>
          <StatusBadge label="安全状态良好" tone="success" />
        </div>
        <div className={styles.factorList}>
          {localFactors.map((factor) => (
            <article key={factor.factorId} className={styles.factorRow}>
              <div className={styles.factorIcon}>{factor.label.slice(0, 1)}</div>
              <div className={styles.factorCopy}>
                <div className={styles.factorTitle}>
                  <h3>{factor.label}</h3>
                  <StatusBadge label={factor.status === "active" ? "已启用" : "建议启用"} tone={factor.status === "active" ? "success" : "warning"} />
                </div>
                <p>{factorDescriptions[factor.kind]}</p>
                {factor.updatedAt && <span>最近更新：{formatSecurityDateTime(factor.updatedAt)}</span>}
              </div>
              <FactorActionButton
                factor={factor}
                onPasswordChange={() => setActiveModal({ type: "password" })}
                onTotpEnroll={() => setActiveModal({ type: "totp_enroll" })}
                onTotpRemove={() => setActiveModal({ type: "totp_remove" })}
                onPasskeyEnroll={() => setActiveModal({ type: "passkey_enroll" })}
                onPasskeyRemove={(credentialId) => setActiveModal({ type: "passkey_remove", credentialId })}
              />
            </article>
          ))}
        </div>
      </section>

      <section className={`${styles.card} ${styles.dangerCard}`}>
        <div>
          <h2>安全恢复</h2>
          <p>撤销除当前设备以外的全部会话。此操作需要确认，执行后其他设备将被立即登出。</p>
        </div>
        <Popconfirm
          title="撤销其他全部会话？"
          content="其他设备上的登录会话将立即失效，用户需要重新登录。当前设备不受影响。"
          type="warning"
          onConfirm={handleRevokeOtherSessions}
          disabled={isRevokingSessions}
        >
          <Button
            type="danger"
            theme="outline"
            loading={isRevokingSessions}
            disabled={isRevokingSessions}
            icon={<IconRefresh />}
          >
            撤销其他会话
          </Button>
        </Popconfirm>
      </section>

      <section className={`${styles.card} ${styles.dangerCard}`}>
        <div>
          <h2>恢复代码</h2>
          <p>生成一次性恢复代码，在无法使用常规验证方式时用于恢复账户访问。每个代码仅可使用一次。</p>
        </div>
        <Button
          type="primary"
          theme="outline"
          icon={<IconKey />}
          onClick={() => setActiveModal({ type: "recovery_codes" })}
        >
          生成恢复代码
        </Button>
      </section>

      {activeModal?.type === "password" && (
        <PasswordChangeModal
          onCancel={() => setActiveModal(null)}
          onSuccess={() => {
            updateFactorStatus("password", "active");
            setActiveModal(null);
          }}
        />
      )}

      {activeModal?.type === "totp_enroll" && (
        <TotpEnrollModal
          onCancel={() => setActiveModal(null)}
          onSuccess={() => {
            addFactor("totp", "身份验证器");
            setActiveModal(null);
          }}
        />
      )}

      {activeModal?.type === "totp_remove" && (
        <TotpRemoveModal
          onCancel={() => setActiveModal(null)}
          onSuccess={() => {
            removeFactor("totp");
            setActiveModal(null);
          }}
        />
      )}

      {activeModal?.type === "passkey_enroll" && (
        <PasskeyEnrollModal
          onCancel={() => setActiveModal(null)}
          onSuccess={() => {
            addFactor("passkey", "通行密钥");
            setActiveModal(null);
          }}
        />
      )}

      {activeModal?.type === "passkey_remove" && (
        <PasskeyRemoveModal
          credentialId={activeModal.credentialId}
          onCancel={() => setActiveModal(null)}
          onSuccess={() => {
            removeFactor("passkey");
            setActiveModal(null);
          }}
        />
      )}

      {activeModal?.type === "recovery_codes" && (
        <RecoveryCodesModal
          onCancel={() => setActiveModal(null)}
          onComplete={() => setActiveModal(null)}
        />
      )}
    </>
  );
}

type FactorActionButtonProps = {
  factor: SecurityFactor;
  onPasswordChange: () => void;
  onTotpEnroll: () => void;
  onTotpRemove: () => void;
  onPasskeyEnroll: () => void;
  onPasskeyRemove: (credentialId: string) => void;
};

function FactorActionButton({
  factor,
  onPasswordChange,
  onTotpEnroll,
  onTotpRemove,
  onPasskeyEnroll,
  onPasskeyRemove,
}: FactorActionButtonProps) {
  if (factor.kind === "password") {
    return (
      <Button theme="outline" icon={<IconLock />} onClick={onPasswordChange}>
        修改密码
      </Button>
    );
  }

  if (factor.kind === "totp") {
    if (factor.status === "active") {
      return (
        <Popconfirm
          title="删除身份验证器？"
          content="删除后，依赖动态验证码的二次验证将不可用。如果你没有其他验证方式，可能无法登录。"
          type="warning"
          onConfirm={onTotpRemove}
        >
          <Button type="danger" theme="outline" icon={<IconDelete />}>
            删除
          </Button>
        </Popconfirm>
      );
    }
    return (
      <Button type="primary" theme="outline" icon={<IconShield />} onClick={onTotpEnroll}>
        设置
      </Button>
    );
  }

  if (factor.kind === "passkey") {
    if (factor.status === "active") {
      return (
        <Popconfirm
          title="删除通行密钥？"
          content="删除后，使用该通行密钥的无密码登录将不可用。"
          type="warning"
          onConfirm={() => onPasskeyRemove(factor.factorId)}
        >
          <Button type="danger" theme="outline" icon={<IconDelete />}>
            删除
          </Button>
        </Popconfirm>
      );
    }
    return (
      <Button type="primary" theme="outline" icon={<IconKey />} onClick={onPasskeyEnroll}>
        设置
      </Button>
    );
  }

  return null;
}

// --- Password Change Modal ---

type PasswordChangeModalProps = {
  onCancel: () => void;
  onSuccess: () => void;
};

function PasswordChangeModal({ onCancel, onSuccess }: PasswordChangeModalProps) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [fieldError, setFieldError] = useState<string>();
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (newPassword.length < PASSWORD_MIN_LENGTH) {
      setFieldError(`新密码至少需要 ${PASSWORD_MIN_LENGTH} 个字符。`);
      return;
    }

    if (newPassword !== confirmPassword) {
      setFieldError("两次输入的新密码不一致。");
      return;
    }

    if (newPassword === currentPassword) {
      setFieldError("新密码不能与当前密码相同。");
      return;
    }

    setFieldError(undefined);
    setIsSubmitting(true);
    try {
      await browserCommands.changePassword(currentPassword, newPassword);
      Toast.success({ content: "密码已更新。" });
      onSuccess();
    } catch {
      Toast.error({ content: "密码更新失败，请确认当前密码是否正确。" });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Modal
      title="修改密码"
      visible
      footer={null}
      width={480}
      maskClosable={false}
      onCancel={onCancel}
    >
      <form className={styles.profileForm} onSubmit={handleSubmit}>
        <label className={styles.profileField} htmlFor="current-password">
          <span>当前密码</span>
          <Input
            id="current-password"
            mode="password"
            value={currentPassword}
            onChange={(value) => {
              setCurrentPassword(value);
              setFieldError(undefined);
            }}
            autoComplete="current-password"
            disabled={isSubmitting}
            required
          />
        </label>
        <label className={styles.profileField} htmlFor="new-password">
          <span>新密码</span>
          <Input
            id="new-password"
            mode="password"
            value={newPassword}
            onChange={(value) => {
              setNewPassword(value);
              setFieldError(undefined);
            }}
            placeholder={`至少 ${PASSWORD_MIN_LENGTH} 个字符`}
            autoComplete="new-password"
            minLength={PASSWORD_MIN_LENGTH}
            disabled={isSubmitting}
            required
          />
          <small>至少 {PASSWORD_MIN_LENGTH} 个字符，请勿使用其他服务的密码。</small>
        </label>
        <label className={styles.profileField} htmlFor="confirm-new-password">
          <span>确认新密码</span>
          <Input
            id="confirm-new-password"
            mode="password"
            value={confirmPassword}
            onChange={(value) => {
              setConfirmPassword(value);
              setFieldError(undefined);
            }}
            autoComplete="new-password"
            minLength={PASSWORD_MIN_LENGTH}
            validateStatus={fieldError ? "error" : "default"}
            aria-invalid={Boolean(fieldError)}
            aria-errormessage={fieldError ? "password-change-error" : undefined}
            disabled={isSubmitting}
            required
          />
          {fieldError && (
            <small id="password-change-error" className={styles.profileError} role="alert">
              {fieldError}
            </small>
          )}
        </label>
        <p className={styles.profileNotice}>
          当前为 Mock 流程，不会校验或修改任何真实密码。后端接入后此操作需要重新验证身份。
        </p>
        <div className={styles.profileActions}>
          <Button theme="outline" onClick={onCancel} disabled={isSubmitting}>取消</Button>
          <Button htmlType="submit" type="primary" theme="solid" loading={isSubmitting} disabled={isSubmitting}>
            更新密码
          </Button>
        </div>
      </form>
    </Modal>
  );
}

// --- TOTP Enrollment Modal ---

type TotpEnrollModalProps = {
  onCancel: () => void;
  onSuccess: () => void;
};

function TotpEnrollModal({ onCancel, onSuccess }: TotpEnrollModalProps) {
  const [phase, setPhase] = useState<"setup" | "confirm">("setup");
  const [secret, setSecret] = useState("");
  const [qrCodeUrl, setQrCodeUrl] = useState("");
  const [code, setCode] = useState("");
  const [fieldError, setFieldError] = useState<string>();
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSetup() {
    setIsSubmitting(true);
    try {
      const result = await browserCommands.enrollTotp();
      setSecret(result.secret);
      setQrCodeUrl(result.qrCodeUrl);
      setPhase("confirm");
    } catch {
      Toast.error({ content: "无法启动身份验证器绑定，请稍后重试。" });
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleConfirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!/^\d{6}$/.test(code.trim())) {
      setFieldError("请输入 6 位数字验证码。");
      return;
    }

    setFieldError(undefined);
    setIsSubmitting(true);
    try {
      await browserCommands.confirmTotpEnrollment(code.trim());
      Toast.success({ content: "身份验证器已绑定。" });
      onSuccess();
    } catch {
      setFieldError("验证码错误，请检查验证器应用中显示的动态码。");
    } finally {
      setIsSubmitting(false);
    }
  }

  if (phase === "setup") {
    return (
      <Modal
        title="绑定身份验证器"
        visible
        footer={null}
        width={480}
        maskClosable={false}
        onCancel={onCancel}
      >
        <div className={styles.profileForm}>
          <p className={styles.profileNotice}>
            绑定身份验证器后，登录时需要输入验证器应用生成的 6 位动态验证码。
          </p>
          <div className={styles.profileActions}>
            <Button theme="outline" onClick={onCancel} disabled={isSubmitting}>取消</Button>
            <Button type="primary" theme="solid" loading={isSubmitting} disabled={isSubmitting} onClick={handleSetup}>
              生成密钥
            </Button>
          </div>
        </div>
      </Modal>
    );
  }

  return (
    <Modal
      title="确认身份验证器"
      visible
      footer={null}
      width={480}
      maskClosable={false}
      onCancel={onCancel}
    >
      <form className={styles.profileForm} onSubmit={handleConfirm}>
        <div className={styles.totpSecret}>
          <p>使用验证器应用扫描以下密钥或手动输入：</p>
          <code>{secret}</code>
          {qrCodeUrl && (
            <a href={qrCodeUrl} target="_blank" rel="noopener noreferrer">
              打开二维码链接（Mock）
            </a>
          )}
        </div>
        <label className={styles.profileField} htmlFor="totp-code">
          <span>验证器动态码</span>
          <Input
            id="totp-code"
            value={code}
            onChange={(value) => {
              setCode(value.replace(/\D/g, "").slice(0, 6));
              setFieldError(undefined);
            }}
            placeholder="6 位数字"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            validateStatus={fieldError ? "error" : "default"}
            aria-invalid={Boolean(fieldError)}
            aria-errormessage={fieldError ? "totp-enroll-error" : undefined}
            disabled={isSubmitting}
            required
          />
          {fieldError && (
            <small id="totp-enroll-error" className={styles.profileError} role="alert">
              {fieldError}
            </small>
          )}
        </label>
        <p className={styles.profileNotice}>当前为 Mock 流程，不会绑定真实 TOTP 密钥。</p>
        <div className={styles.profileActions}>
          <Button theme="outline" onClick={onCancel} disabled={isSubmitting}>取消</Button>
          <Button htmlType="submit" type="primary" theme="solid" loading={isSubmitting} disabled={isSubmitting}>
            确认绑定
          </Button>
        </div>
      </form>
    </Modal>
  );
}

// --- TOTP Remove Modal ---

type TotpRemoveModalProps = {
  onCancel: () => void;
  onSuccess: () => void;
};

function TotpRemoveModal({ onCancel, onSuccess }: TotpRemoveModalProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleRemove() {
    setIsSubmitting(true);
    try {
      await browserCommands.removeTotp();
      Toast.success({ content: "身份验证器已删除。" });
      onSuccess();
    } catch {
      Toast.error({ content: "删除失败，请稍后重试。" });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Modal
      title="删除身份验证器"
      visible
      width={460}
      maskClosable={false}
      onCancel={onCancel}
      footer={
        <>
          <Button theme="outline" onClick={onCancel} disabled={isSubmitting}>取消</Button>
          <Button type="danger" theme="solid" loading={isSubmitting} disabled={isSubmitting} onClick={handleRemove}>
            确认删除
          </Button>
        </>
      }
    >
      <Banner
        type="warning"
        fullMode={false}
        bordered
        closeIcon={null}
        description="删除后，依赖动态验证码的二次验证将不可用。如果你没有其他验证方式，可能无法登录。"
      />
      <p className={styles.profileNotice}>当前为 Mock 流程，不会修改真实验证配置。</p>
    </Modal>
  );
}

// --- Passkey Enrollment Modal ---

type PasskeyEnrollModalProps = {
  onCancel: () => void;
  onSuccess: () => void;
};

function PasskeyEnrollModal({ onCancel, onSuccess }: PasskeyEnrollModalProps) {
  const [phase, setPhase] = useState<"start" | "pending">("start");
  const [error, setError] = useState<string>();

  async function handleEnroll() {
    setPhase("pending");
    setError(undefined);
    try {
      const result = await browserCommands.startPasskeyEnrollment();
      // Mock: a real implementation would call navigator.credentials.create()
      // with the options returned by the backend, then send the attestation.
      await browserCommands.completePasskeyEnrollment(result.options);
      Toast.success({ content: "通行密钥已添加。" });
      onSuccess();
    } catch {
      setError("通行密钥注册失败，请确认设备支持并已解锁。");
      setPhase("start");
    }
  }

  return (
    <Modal
      title="添加通行密钥"
      visible
      footer={null}
      width={480}
      maskClosable={false}
      onCancel={onCancel}
    >
      <div className={styles.profileForm}>
        <div className={styles.totpSecret}>
          <p>使用设备生物识别或安全密钥注册通行密钥，实现抗钓鱼无密码登录。</p>
        </div>
        {error && (
          <Banner type="danger" fullMode={false} bordered closeIcon={null} description={error} />
        )}
        <p className={styles.profileNotice}>
          当前为 Mock 流程，不会调用 WebAuthn API。后端接入后将触发真实的通行密钥注册。
        </p>
        <div className={styles.profileActions}>
          <Button theme="outline" onClick={onCancel} disabled={phase === "pending"}>取消</Button>
          <Button
            type="primary"
            theme="solid"
            loading={phase === "pending"}
            disabled={phase === "pending"}
            icon={<IconKey />}
            onClick={handleEnroll}
          >
            {phase === "pending" ? "正在注册…" : "开始注册"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

// --- Passkey Remove Modal ---

type PasskeyRemoveModalProps = {
  credentialId: string;
  onCancel: () => void;
  onSuccess: () => void;
};

function PasskeyRemoveModal({ credentialId, onCancel, onSuccess }: PasskeyRemoveModalProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleRemove() {
    setIsSubmitting(true);
    try {
      await browserCommands.removePasskey(credentialId);
      Toast.success({ content: "通行密钥已删除。" });
      onSuccess();
    } catch {
      Toast.error({ content: "删除失败，请稍后重试。" });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Modal
      title="删除通行密钥"
      visible
      width={460}
      maskClosable={false}
      onCancel={onCancel}
      footer={
        <>
          <Button theme="outline" onClick={onCancel} disabled={isSubmitting}>取消</Button>
          <Button type="danger" theme="solid" loading={isSubmitting} disabled={isSubmitting} onClick={handleRemove}>
            确认删除
          </Button>
        </>
      }
    >
      <Banner
        type="warning"
        fullMode={false}
        bordered
        closeIcon={null}
        description="删除后，使用该通行密钥的无密码登录将不可用。"
      />
      <p className={styles.profileNotice}>当前为 Mock 流程，不会修改真实凭据。</p>
    </Modal>
  );
}

// --- Recovery Codes Modal ---

type RecoveryCodesModalProps = {
  onCancel: () => void;
  onComplete: () => void;
};

function RecoveryCodesModal({ onCancel, onComplete }: RecoveryCodesModalProps) {
  const [phase, setPhase] = useState<"generate" | "display">("generate");
  const [codes, setCodes] = useState<string[]>([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [hasCopied, setHasCopied] = useState(false);

  async function handleGenerate() {
    setIsGenerating(true);
    try {
      const result = await browserCommands.generateRecoveryCodes();
      setCodes(result.codes);
      setPhase("display");
    } catch {
      Toast.error({ content: "生成恢复代码失败，请稍后重试。" });
    } finally {
      setIsGenerating(false);
    }
  }

  function handleCopy() {
    const text = codes.join("\n");
    navigator.clipboard.writeText(text).then(() => {
      setHasCopied(true);
      Toast.success({ content: "恢复代码已复制到剪贴板。" });
    }).catch(() => {
      Toast.error({ content: "复制失败，请手动抄写。" });
    });
  }

  if (phase === "generate") {
    return (
      <Modal
        title="生成恢复代码"
        visible
        footer={null}
        width={480}
        maskClosable={false}
        onCancel={onCancel}
      >
        <div className={styles.profileForm}>
          <p className={styles.profileNotice}>
            恢复代码用于在无法使用常规验证方式时恢复账户访问。每个代码仅可使用一次。
            生成后请妥善保存，关闭此窗口后将无法再次查看。
          </p>
          <div className={styles.profileActions}>
            <Button theme="outline" onClick={onCancel} disabled={isGenerating}>取消</Button>
            <Button type="primary" theme="solid" loading={isGenerating} disabled={isGenerating} onClick={handleGenerate}>
              生成恢复代码
            </Button>
          </div>
        </div>
      </Modal>
    );
  }

  return (
    <Modal
      title="恢复代码"
      visible
      width={520}
      maskClosable={false}
      onCancel={onComplete}
      footer={
        <>
          <Button theme="outline" onClick={handleCopy} disabled={!codes.length}>
            {hasCopied ? "已复制" : "复制全部"}
          </Button>
          <Button type="primary" theme="solid" onClick={onComplete}>
            已保存，关闭
          </Button>
        </>
      }
    >
      <Banner
        type="info"
        fullMode={false}
        bordered
        closeIcon={null}
        description="请将恢复代码保存到安全位置。每个代码仅可使用一次。关闭此窗口后将无法再次查看这些代码。"
      />
      <div className={styles.recoveryCodesGrid}>
        {codes.map((code, index) => (
          <code key={index}>{code}</code>
        ))}
      </div>
      <p className={styles.profileNotice}>当前为 Mock 流程，生成的代码不会持久化。</p>
    </Modal>
  );
}
