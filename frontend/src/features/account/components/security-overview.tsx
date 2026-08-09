//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Security overview panel
//

"use client";

import type { FormEvent, MutableRefObject, ReactNode } from "react";
import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Banner, Button, Input, Modal, Popconfirm, Toast } from "@douyinfe/semi-ui";
import { IconDelete, IconKey, IconShield, IconRefresh, IconLock } from "@douyinfe/semi-icons";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import type {
  AccountReauthenticationAction,
  ReauthenticationChallenge,
  SecurityPasskey,
  SecuritySummary,
  TotpEnrollment,
} from "@/features/account/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { isApiError } from "@/lib/api/api-error";
import { USE_MOCK_DATA_SOURCE } from "@/lib/api/data-source-mode";
import {
  getPasskeyAssertion,
  isWebAuthnSupported,
} from "@/features/account/utils/webauthn";
import {
  passkeyCredentialCreator,
  runPasskeyEnrollmentCeremony,
} from "@/features/account/utils/passkey-enrollment";
import styles from "./account-panels.module.css";

type SecurityOverviewProps = {
  securitySummary: SecuritySummary;
};

type ActiveModal =
  | { type: "password" }
  | { type: "totp_enroll" }
  | { type: "totp_remove" }
  | { type: "passkey_enroll" }
  | { type: "passkey_remove"; passkeyId: string }
  | { type: "recovery_codes" }
  | null;

const PASSWORD_MIN_LENGTH = 12;

export function SecurityOverview({ securitySummary }: SecurityOverviewProps) {
  const router = useRouter();
  const [activeModal, setActiveModal] = useState<ActiveModal>(null);
  const [isRevokingSessions, setIsRevokingSessions] = useState(false);
  const [mockSummary, setMockSummary] = useState<SecuritySummary>(securitySummary);
  const displayedSummary = USE_MOCK_DATA_SOURCE ? mockSummary : securitySummary;

  function refreshAuthoritativeState(): void {
    if (!USE_MOCK_DATA_SOURCE) router.refresh();
  }

  async function handleRevokeOtherSessions(): Promise<void> {
    setIsRevokingSessions(true);
    try {
      const { revoked } = await browserCommands.revokeOtherSessions();
      Toast.success({ content: revoked === 0 ? "没有需要撤销的其他会话。" : `已撤销 ${revoked} 个其他会话。` });
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
        description="管理登录凭据和多重验证方式。通行密钥变更需要重新验证身份。"
      />
      <section className={styles.card}>
        <div className={styles.cardHeading}>
          <div>
            <span className={styles.label}>AUTHENTICATION</span>
            <h2>验证方式</h2>
          </div>
          <StatusBadge
            label={USE_MOCK_DATA_SOURCE ? "Mock 预览状态" : "身份提供方实时状态"}
            tone={USE_MOCK_DATA_SOURCE ? "info" : "neutral"}
          />
        </div>
        <div className={styles.factorList}>
          <SecurityFactorRow
            icon="密"
            label="账户密码"
            statusLabel={displayedSummary.password.set ? "已设置" : "未设置"}
            active={displayedSummary.password.set}
            description="用于基础凭据验证，建议避免与其他服务复用。"
            action={(
              <Button theme="outline" icon={<IconLock />} onClick={() => setActiveModal({ type: "password" })}>
                修改密码
              </Button>
            )}
          />
          <SecurityFactorRow
            icon="验"
            label="身份验证器"
            statusLabel={displayedSummary.totp.enabled ? "已启用" : "未启用"}
            active={displayedSummary.totp.enabled}
            description="使用身份验证器生成的一次性动态验证码。"
            action={(
              displayedSummary.totp.enabled ? (
                <Button type="danger" theme="outline" icon={<IconDelete />} onClick={() => setActiveModal({ type: "totp_remove" })}>
                  删除
                </Button>
              ) : (
                <Button type="primary" theme="outline" icon={<IconShield />} onClick={() => setActiveModal({ type: "totp_enroll" })}>
                  设置
                </Button>
              )
            )}
          />
          {displayedSummary.passkeys.map((passkey) => (
            <PasskeyRow
              key={passkey.passkeyId}
              passkey={passkey}
              onRemove={() => setActiveModal({ type: "passkey_remove", passkeyId: passkey.passkeyId })}
            />
          ))}
          <SecurityFactorRow
            icon="钥"
            label={displayedSummary.passkeys.length === 0 ? "尚未添加通行密钥" : "添加其他通行密钥"}
            statusLabel={displayedSummary.passkeys.length === 0 ? "建议启用" : "可添加"}
            active={false}
            description="使用设备生物识别或安全密钥进行抗钓鱼验证。"
            action={(
              <Button type="primary" theme="outline" icon={<IconKey />} onClick={() => setActiveModal({ type: "passkey_enroll" })}>
                添加
              </Button>
            )}
          />
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

      {USE_MOCK_DATA_SOURCE && <section className={`${styles.card} ${styles.dangerCard}`}>
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
      </section>}

      {activeModal?.type === "password" && (
        <PasswordChangeModal
          onCancel={() => setActiveModal(null)}
          onSuccess={() => {
            if (USE_MOCK_DATA_SOURCE) {
              setMockSummary((current) => ({ ...current, password: { set: true } }));
            }
            refreshAuthoritativeState();
            setActiveModal(null);
          }}
        />
      )}

      {activeModal?.type === "totp_enroll" && (
        <TotpEnrollModal
          onCancel={() => setActiveModal(null)}
          onSuccess={() => {
            if (USE_MOCK_DATA_SOURCE) {
              setMockSummary((current) => ({ ...current, totp: { enabled: true } }));
            }
            refreshAuthoritativeState();
            setActiveModal(null);
          }}
        />
      )}

      {activeModal?.type === "totp_remove" && (
        <TotpRemoveModal
          onCancel={() => setActiveModal(null)}
          onSuccess={() => {
            if (USE_MOCK_DATA_SOURCE) {
              setMockSummary((current) => ({ ...current, totp: { enabled: false } }));
            }
            refreshAuthoritativeState();
            setActiveModal(null);
          }}
        />
      )}

      {activeModal?.type === "passkey_enroll" && (
        <PasskeyEnrollModal
          onCancel={() => setActiveModal(null)}
          onSuccess={(passkeyId) => {
            if (USE_MOCK_DATA_SOURCE) {
              setMockSummary((current) => ({
                ...current,
                passkeys: [...current.passkeys, { passkeyId, state: "active", createdAt: new Date().toISOString() }],
              }));
            }
            refreshAuthoritativeState();
            setActiveModal(null);
          }}
        />
      )}

      {activeModal?.type === "passkey_remove" && (
        <PasskeyRemoveModal
          passkeyId={activeModal.passkeyId}
          onCancel={() => setActiveModal(null)}
          onSuccess={() => {
            if (USE_MOCK_DATA_SOURCE) {
              setMockSummary((current) => ({
                ...current,
                passkeys: current.passkeys.filter((passkey) => passkey.passkeyId !== activeModal.passkeyId),
              }));
            }
            refreshAuthoritativeState();
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

type SecurityFactorRowProps = {
  icon: string;
  label: string;
  statusLabel: string;
  active: boolean;
  description: string;
  detail?: string;
  action?: ReactNode;
};

function SecurityFactorRow({
  icon,
  label,
  statusLabel,
  active,
  description,
  detail,
  action,
}: SecurityFactorRowProps) {
  return (
    <article className={styles.factorRow}>
      <div className={styles.factorIcon}>{icon}</div>
      <div className={styles.factorCopy}>
        <div className={styles.factorTitle}>
          <h3>{label}</h3>
          <StatusBadge label={statusLabel} tone={active ? "success" : "warning"} />
        </div>
        <p>{description}</p>
        {detail && <span>{detail}</span>}
      </div>
      {action}
    </article>
  );
}

function PasskeyRow({ passkey, onRemove }: { passkey: SecurityPasskey; onRemove: () => void }) {
  return (
    <SecurityFactorRow
      icon="钥"
      label="通行密钥"
      statusLabel={passkey.state === "active" ? "已启用" : "等待确认"}
      active={passkey.state === "active"}
      description={`凭据标识：${passkey.passkeyId}`}
      detail={passkey.createdAt === null ? "添加时间：未知" : `添加时间：${formatSecurityDateTime(passkey.createdAt)}`}
      action={(
        <Button type="danger" theme="outline" icon={<IconDelete />} onClick={onRemove}>
          删除
        </Button>
      )}
    />
  );
}

// --- Password Change Modal ---

type PasswordChangeModalProps = {
  onCancel: () => void;
  onSuccess: () => void;
};

function PasswordChangeModal({ onCancel, onSuccess }: PasswordChangeModalProps) {
  const router = useRouter();
  const browserOperation = useRef<AbortController | null>(null);
  const [phase, setPhase] = useState<"details" | "reauth">("details");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [fieldError, setFieldError] = useState<string>();

  function handleDetails(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();

    if (newPassword.length < PASSWORD_MIN_LENGTH) {
      setFieldError(`新密码至少需要 ${PASSWORD_MIN_LENGTH} 个字符。`);
      return;
    }

    if (newPassword !== confirmPassword) {
      setFieldError("两次输入的新密码不一致。");
      return;
    }

    setFieldError(undefined);
    setPhase("reauth");
  }

  function handleCancel(): void {
    browserOperation.current?.abort();
    browserOperation.current = null;
    onCancel();
  }

  async function changePassword(reauthToken: string, signal: AbortSignal): Promise<void> {
    try {
      await browserCommands.changePassword(newPassword, reauthToken, { signal });
    } catch (error) {
      if (isApiError(error) && error.kind === "unauthorized") {
        setNewPassword("");
        setConfirmPassword("");
        Toast.info({ content: "账户安全状态已变更，请重新登录以确认凭据状态。" });
        router.replace("/login");
        router.refresh();
        return;
      }
      throw error;
    }
    setNewPassword("");
    setConfirmPassword("");
    Toast.success({ content: "密码已更新，其他登录会话已失效。" });
    onSuccess();
  }

  return (
    <Modal
      title="修改密码"
      visible
      footer={null}
      width={480}
      maskClosable={false}
      onCancel={handleCancel}
    >
      {phase === "details" ? <form className={styles.profileForm} method="post" onSubmit={handleDetails}>
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
            required
          />
          {fieldError && (
            <small id="password-change-error" className={styles.profileError} role="alert">
              {fieldError}
            </small>
          )}
        </label>
        <p className={styles.profileNotice}>
          下一步将重新验证当前密码；新密码只会发送到最终密码修改请求。
        </p>
        <div className={styles.profileActions}>
          <Button theme="outline" onClick={handleCancel}>取消</Button>
          <Button htmlType="submit" type="primary" theme="solid">
            下一步
          </Button>
        </div>
      </form> : (
        <AccountReauthenticationForm
          action="account.password.change"
          target=""
          submitLabel="验证并更新密码"
          browserOperationRef={browserOperation}
          onGranted={changePassword}
          onCancel={handleCancel}
          operationError="密码更新失败，请重新开始。此次授权不会被重复使用。"
        />
      )}
    </Modal>
  );
}

// --- TOTP Enrollment Modal ---

type TotpEnrollModalProps = {
  onCancel: () => void;
  onSuccess: () => void;
};

function TotpEnrollModal({ onCancel, onSuccess }: TotpEnrollModalProps) {
  const browserOperation = useRef<AbortController | null>(null);
  const [enrollment, setEnrollment] = useState<TotpEnrollment | null>(null);
  const [code, setCode] = useState("");
  const [fieldError, setFieldError] = useState<string>();
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleCancel(): Promise<void> {
    if (isSubmitting) return;
    browserOperation.current?.abort();
    browserOperation.current = null;
    if (enrollment !== null) {
      setIsSubmitting(true);
      try {
        await browserCommands.cancelTotpEnrollment(enrollment.enrollmentToken);
      } catch {
        Toast.error({ content: "无法取消当前绑定，请重试后再关闭。" });
        setIsSubmitting(false);
        return;
      }
    }
    setEnrollment(null);
    setCode("");
    onCancel();
  }

  async function beginEnrollment(reauthToken: string, signal: AbortSignal): Promise<void> {
    setEnrollment(await browserCommands.beginTotpEnrollment(reauthToken, { signal }));
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
      if (enrollment === null) return;
      await browserCommands.confirmTotpEnrollment({
        enrollmentToken: enrollment.enrollmentToken,
        code: code.trim(),
      });
      setEnrollment(null);
      setCode("");
      Toast.success({ content: "身份验证器已绑定。" });
      onSuccess();
    } catch (error) {
      if (isApiError(error) && error.kind === "validation") {
        setEnrollment(null);
        setCode("");
        setFieldError("验证码错误，本次绑定已结束，请重新验证后开始新的绑定。");
      } else {
        setFieldError("确认失败，请稍后重试当前验证码。");
      }
    } finally {
      setIsSubmitting(false);
    }
  }

  if (enrollment === null) {
    return (
      <Modal
        title="绑定身份验证器"
        visible
        footer={null}
        width={480}
        maskClosable={false}
        onCancel={() => void handleCancel()}
      >
        <div className={styles.profileForm}>
          <p className={styles.profileNotice}>
            绑定身份验证器后，登录时需要输入验证器应用生成的 6 位动态验证码。
          </p>
          {fieldError && <Banner type="danger" fullMode={false} bordered closeIcon={null} description={fieldError} />}
          <AccountReauthenticationForm
            action="account.totp.enroll"
            target=""
            submitLabel="验证并生成密钥"
            browserOperationRef={browserOperation}
            onGranted={beginEnrollment}
            onCancel={() => void handleCancel()}
            operationError="无法启动身份验证器绑定，请重新开始。此次授权不会被重复使用。"
          />
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
      onCancel={() => void handleCancel()}
    >
      <form className={styles.profileForm} method="post" onSubmit={handleConfirm}>
        <div className={styles.totpSecret}>
          <p>使用验证器应用扫描以下密钥或手动输入：</p>
          <code>{enrollment.secret}</code>
          {enrollment.otpauthUri && (
            <a href={enrollment.otpauthUri}>
              在身份验证器应用中打开
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
        <p className={styles.profileNotice}>密钥仅在此窗口显示；关闭后需要重新开始绑定。</p>
        <div className={styles.profileActions}>
          <Button theme="outline" onClick={() => void handleCancel()} disabled={isSubmitting}>取消</Button>
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
  const browserOperation = useRef<AbortController | null>(null);

  function handleCancel(): void {
    browserOperation.current?.abort();
    browserOperation.current = null;
    onCancel();
  }

  async function handleRemove(reauthToken: string, signal: AbortSignal): Promise<void> {
    await browserCommands.removeTotp(reauthToken, { signal });
    Toast.success({ content: "身份验证器已删除。" });
    onSuccess();
  }

  return (
    <Modal
      title="删除身份验证器"
      visible
      width={460}
      maskClosable={false}
      onCancel={handleCancel}
      footer={null}
    >
      <Banner
        type="warning"
        fullMode={false}
        bordered
        closeIcon={null}
        description="删除后，依赖动态验证码的二次验证将不可用。如果你没有其他验证方式，可能无法登录。"
      />
      <AccountReauthenticationForm
        action="account.totp.remove"
        target=""
        submitLabel="验证并删除"
        browserOperationRef={browserOperation}
        onGranted={handleRemove}
        onCancel={handleCancel}
        operationError="删除身份验证器失败，请重新开始。此次授权不会被重复使用。"
        destructive
      />
    </Modal>
  );
}

// --- Passkey Enrollment Modal ---

type PasskeyEnrollModalProps = {
  onCancel: () => void;
  onSuccess: (passkeyId: string) => void;
};

function PasskeyEnrollModal({ onCancel, onSuccess }: PasskeyEnrollModalProps) {
  const browserOperation = useRef<AbortController | null>(null);

  function handleCancel(): void {
    browserOperation.current?.abort();
    browserOperation.current = null;
    onCancel();
  }

  async function enroll(reauthToken: string, signal: AbortSignal): Promise<void> {
    const passkeyId = await runPasskeyEnrollmentCeremony({
      reauthToken,
      signal,
      commands: browserCommands,
      createCredential: passkeyCredentialCreator(USE_MOCK_DATA_SOURCE),
    });
    Toast.success({ content: "通行密钥已添加。" });
    onSuccess(passkeyId);
  }

  return (
    <Modal
      title="添加通行密钥"
      visible
      footer={null}
      width={480}
      maskClosable={false}
      onCancel={handleCancel}
    >
      <div className={styles.profileForm}>
        <div className={styles.totpSecret}>
          <p>使用设备生物识别或安全密钥注册通行密钥，实现抗钓鱼无密码登录。</p>
        </div>
        <AccountReauthenticationForm
          action="account.passkey.enroll"
          target=""
          submitLabel="验证并开始注册"
          browserOperationRef={browserOperation}
          onGranted={enroll}
          onCancel={handleCancel}
          operationError="通行密钥操作失败，请重新开始。此次授权不会被重复使用。"
        />
      </div>
    </Modal>
  );
}

// --- Passkey Remove Modal ---

type PasskeyRemoveModalProps = {
  passkeyId: string;
  onCancel: () => void;
  onSuccess: () => void;
};

function PasskeyRemoveModal({ passkeyId, onCancel, onSuccess }: PasskeyRemoveModalProps) {
  const browserOperation = useRef<AbortController | null>(null);

  function handleCancel(): void {
    browserOperation.current?.abort();
    browserOperation.current = null;
    onCancel();
  }

  async function remove(reauthToken: string, signal: AbortSignal): Promise<void> {
    try {
      await browserCommands.removePasskey(passkeyId, reauthToken, { signal });
    } catch (error) {
      if (isApiError(error) && error.kind === "not_found") {
        Toast.info({ content: "该通行密钥已不存在，正在刷新安全状态。" });
        onSuccess();
        return;
      }
      throw error;
    }
    Toast.success({ content: "通行密钥已删除。" });
    onSuccess();
  }

  return (
    <Modal
      title="删除通行密钥"
      visible
      width={460}
      maskClosable={false}
      onCancel={handleCancel}
      footer={null}
    >
      <Banner
        type="warning"
        fullMode={false}
        bordered
        closeIcon={null}
        description="删除后，使用该通行密钥的无密码登录将不可用。"
      />
      <AccountReauthenticationForm
        action="account.passkey.remove"
        target={passkeyId}
        submitLabel="验证并删除"
        browserOperationRef={browserOperation}
        onGranted={remove}
        onCancel={handleCancel}
        operationError="通行密钥操作失败，请重新开始。此次授权不会被重复使用。"
        destructive
      />
    </Modal>
  );
}

function replaceAbortController(
  reference: MutableRefObject<AbortController | null>,
): AbortController {
  reference.current?.abort();
  const controller = new AbortController();
  reference.current = controller;
  return controller;
}

type AccountReauthenticationFormProps = {
  action: AccountReauthenticationAction;
  target: string;
  submitLabel: string;
  browserOperationRef: MutableRefObject<AbortController | null>;
  onGranted: (reauthToken: string, signal: AbortSignal) => Promise<void>;
  onCancel: () => void;
  operationError: string;
  destructive?: boolean;
};

function AccountReauthenticationForm({
  action,
  target,
  submitLabel,
  browserOperationRef,
  onGranted,
  onCancel,
  operationError,
  destructive = false,
}: AccountReauthenticationFormProps) {
  const [password, setPassword] = useState("");
  const [challenge, setChallenge] = useState<ReauthenticationChallenge | null>(null);
  const [method, setMethod] = useState<"totp" | "passkey">("totp");
  const [totpCode, setTotpCode] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string>();

  async function finishWithGrant(reauthToken: string, signal: AbortSignal): Promise<void> {
    setChallenge(null);
    setTotpCode("");
    await onGranted(reauthToken, signal);
  }

  async function runGrantedOperation(reauthToken: string, signal: AbortSignal): Promise<void> {
    try {
      await finishWithGrant(reauthToken, signal);
    } catch {
      setError(operationError);
    } finally {
      browserOperationRef.current = null;
    }
  }

  async function requestGrant(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setError(undefined);
    if (
      action === "account.passkey.enroll" &&
      !USE_MOCK_DATA_SOURCE &&
      !isWebAuthnSupported()
    ) {
      setError("当前浏览器不支持通行密钥，请更换受支持的浏览器或设备。");
      return;
    }
    setIsSubmitting(true);
    const controller = replaceAbortController(browserOperationRef);
    try {
      const outcome = await browserCommands.requestReauthentication(
        { action, target, password },
        { signal: controller.signal },
      );
      setPassword("");
      if (outcome.status === "granted") {
        await runGrantedOperation(outcome.reauthToken, controller.signal);
        return;
      }
      const defaultMethod = outcome.availableMethods[0];
      setMethod(defaultMethod);
      setChallenge(outcome);
    } catch {
      setPassword("");
      setError("身份验证失败，请重新输入密码后再试。");
    } finally {
      setIsSubmitting(false);
    }
  }

  async function completeMfa(): Promise<void> {
    if (challenge === null) return;
    setError(undefined);
    setIsSubmitting(true);
    const controller = replaceAbortController(browserOperationRef);
    let grantedToken: string;
    try {
      const grant = method === "totp"
        ? await browserCommands.completeReauthenticationMfa({
            reauthToken: challenge.reauthToken,
            method,
            code: totpCode,
          }, { signal: controller.signal })
        : await browserCommands.completeReauthenticationMfa({
            reauthToken: challenge.reauthToken,
            method,
            passkeyAssertion: await getPasskeyAssertion(
              challenge.passkeyRequestOptions,
              controller.signal,
            ),
          }, { signal: controller.signal });
      grantedToken = grant.reauthToken;
    } catch {
      browserOperationRef.current = null;
      setError("二次验证失败，请重试或选择其他验证方式。");
      setIsSubmitting(false);
      return;
    }

    try {
      await runGrantedOperation(grantedToken, controller.signal);
    } finally {
      setIsSubmitting(false);
    }
  }

  if (challenge !== null) {
    return (
      <div className={styles.profileForm}>
        {challenge.availableMethods.length > 1 && (
          <div className={styles.profileActions}>
            {challenge.availableMethods.map((availableMethod) => (
              <Button
                key={availableMethod}
                theme={method === availableMethod ? "solid" : "outline"}
                onClick={() => {
                  setMethod(availableMethod);
                  setError(undefined);
                }}
                disabled={isSubmitting}
              >
                {availableMethod === "totp" ? "动态验证码" : "通行密钥"}
              </Button>
            ))}
          </div>
        )}
        {method === "totp" && (
          <label className={styles.profileField} htmlFor={`account-reauth-totp-${action}`}>
            <span>动态验证码</span>
            <Input
              id={`account-reauth-totp-${action}`}
              value={totpCode}
              onChange={(value) => setTotpCode(value)}
              maxLength={8}
              autoComplete="one-time-code"
              disabled={isSubmitting}
            />
          </label>
        )}
        {error && <Banner type="danger" fullMode={false} bordered closeIcon={null} description={error} />}
        <div className={styles.profileActions}>
          <Button theme="outline" onClick={onCancel} disabled={isSubmitting}>取消</Button>
          <Button
            type={destructive ? "danger" : "primary"}
            theme="solid"
            loading={isSubmitting}
            disabled={isSubmitting || (method === "totp" && totpCode.length === 0)}
            onClick={completeMfa}
          >
            {method === "totp" ? "验证验证码" : "使用通行密钥验证"}
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form className={styles.profileForm} method="post" onSubmit={requestGrant}>
      <label className={styles.profileField} htmlFor={`account-reauth-password-${action}`}>
        <span>当前密码</span>
        <Input
          id={`account-reauth-password-${action}`}
          mode="password"
          value={password}
          onChange={(value) => {
            setPassword(value);
            setError(undefined);
          }}
          autoComplete="current-password"
          disabled={isSubmitting}
          required
        />
      </label>
      <p className={styles.profileNotice}>密码仅用于本次重新验证，不会包含在后续账户安全变更请求中。</p>
      {error && <Banner type="danger" fullMode={false} bordered closeIcon={null} description={error} />}
      <div className={styles.profileActions}>
        <Button theme="outline" onClick={onCancel} disabled={isSubmitting}>取消</Button>
        <Button
          htmlType="submit"
          type={destructive ? "danger" : "primary"}
          theme="solid"
          loading={isSubmitting}
          disabled={isSubmitting || password.length === 0}
          icon={<IconKey />}
        >
          {submitLabel}
        </Button>
      </div>
    </form>
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
