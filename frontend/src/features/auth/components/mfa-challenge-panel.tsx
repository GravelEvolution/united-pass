//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: MFA challenge input panel
//

"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import { Banner, Button, Input } from "@douyinfe/semi-ui";
import {
  IconAlertTriangle,
  IconClose,
  IconHourglass,
  IconKey,
  IconLock,
  IconShield,
} from "@douyinfe/semi-icons";
import type { MfaMethod } from "@/features/auth/types";
import { isApiError } from "@/lib/api/api-error";
import styles from "./credential-panel.module.css";

type MfaChallengePanelProps = {
  mfaToken: string;
  availableMethods: MfaMethod[];
  onSuccess: (redirectUrl: string) => void;
  onCancel: () => void;
  /**
   * Real-mode seam (P3.9): submits the code against the P1 Session API.
   * When provided, verification performs a real network round-trip and the
   * mock artifacts (demo state buttons, MOCK PREVIEW badge) are hidden;
   * when absent, the frozen mock behavior is kept.
   */
  onVerify?: (method: MfaMethod, code: string) => Promise<void>;
};

type MfaPhase =
  | { phase: "active" }
  | { phase: "submitting" }
  | { phase: "expired" }
  | { phase: "too_many_attempts" };

const METHOD_LABELS: Record<MfaMethod, string> = {
  totp: "验证器应用",
  passkey: "通行密钥",
  recovery_code: "恢复代码",
};

const METHOD_ORDER: MfaMethod[] = ["totp", "passkey", "recovery_code"];

const MAX_ATTEMPTS = 5;
const MOCK_REDIRECT_URL = "/account";

function pickDefaultMethod(methods: MfaMethod[]): MfaMethod {
  for (const method of METHOD_ORDER) {
    if (methods.includes(method)) {
      return method;
    }
  }
  return methods[0];
}

export function MfaChallengePanel({
  mfaToken,
  availableMethods,
  onSuccess,
  onCancel,
  onVerify,
}: MfaChallengePanelProps) {
  const isRealMode = onVerify !== undefined;
  const [selectedMethod, setSelectedMethod] = useState<MfaMethod>(() =>
    pickDefaultMethod(availableMethods),
  );
  const [phase, setPhase] = useState<MfaPhase>({ phase: "active" });
  const [codeValue, setCodeValue] = useState("");
  const [recoveryValue, setRecoveryValue] = useState("");
  const [fieldError, setFieldError] = useState<string>();
  const [attempts, setAttempts] = useState(0);

  function completeChallengeSuccess() {
    setPhase({ phase: "submitting" });
    window.setTimeout(() => {
      onSuccess(MOCK_REDIRECT_URL);
    }, 600);
  }

  function verifyErrorMessage(error: unknown): string {
    if (isApiError(error)) {
      if (error.kind === "rate_limited") {
        setPhase({ phase: "too_many_attempts" });
      }
      return error.message;
    }
    return "验证失败，请重试。";
  }

  async function handleRealTotpSubmit(code: string) {
    if (!onVerify) return;
    setPhase({ phase: "submitting" });
    try {
      await onVerify("totp", code);
      onSuccess(MOCK_REDIRECT_URL);
    } catch (error) {
      setPhase({ phase: "active" });
      setFieldError(verifyErrorMessage(error));
    }
  }

  async function handleRealRecoverySubmit(code: string) {
    if (!onVerify) return;
    setPhase({ phase: "submitting" });
    try {
      await onVerify("recovery_code", code);
      onSuccess(MOCK_REDIRECT_URL);
    } catch (error) {
      setPhase({ phase: "active" });
      const nextAttempts = attempts + 1;
      setAttempts(nextAttempts);
      if (nextAttempts >= MAX_ATTEMPTS) {
        setPhase({ phase: "too_many_attempts" });
        return;
      }
      setFieldError(verifyErrorMessage(error));
    }
  }

  function handleTotpSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const code = codeValue.trim();

    if (!/^\d{6}$/.test(code)) {
      setFieldError("请输入 6 位数字验证码。");
      return;
    }

    if (onVerify) {
      void handleRealTotpSubmit(code);
      return;
    }

    // Mock: any 6-digit code from an authenticator app is accepted.
    completeChallengeSuccess();
  }

  function handleRecoverySubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const code = recoveryValue.trim();

    if (code.length < 8) {
      const nextAttempts = attempts + 1;
      setAttempts(nextAttempts);
      if (nextAttempts >= MAX_ATTEMPTS) {
        setPhase({ phase: "too_many_attempts" });
        return;
      }
      setFieldError(`恢复代码无效。剩余尝试次数 ${MAX_ATTEMPTS - nextAttempts} 次。`);
      return;
    }

    if (onVerify) {
      void handleRealRecoverySubmit(code);
      return;
    }

    completeChallengeSuccess();
  }

  function handlePasskey() {
    // Mock: a real passkey flow would call the WebAuthn API here. This
    // simulates a successful assertion without touching any credential.
    completeChallengeSuccess();
  }

  if (phase.phase === "expired") {
    return (
      <div className={styles.panel}>
        <div className={styles.heading}>
          {!isRealMode && <span className={styles.mockBadge}>MOCK PREVIEW</span>}
          <h1>验证已过期</h1>
          <p>多因素验证挑战已超时，请返回登录重新发起。</p>
        </div>
        <div role="alert">
          <Banner
            type="warning"
            icon={<IconHourglass />}
            description="出于安全考虑，验证挑战有效时间较短。请重新登录以获取新的验证挑战。"
          />
        </div>
        <div className={styles.actions}>
          <Button theme="outline" size="large" onClick={onCancel}>返回登录</Button>
        </div>
        {!isRealMode && (
          <p className={styles.notice}>当前为界面 mock，不会执行真实的多因素验证。</p>
        )}
      </div>
    );
  }

  if (phase.phase === "too_many_attempts") {
    return (
      <div className={styles.panel}>
        <div className={styles.heading}>
          {!isRealMode && <span className={styles.mockBadge}>MOCK PREVIEW</span>}
          <h1>尝试次数过多</h1>
          <p>为保护账户安全，多因素验证已被暂时锁定。</p>
        </div>
        <div role="alert">
          <Banner
            type="danger"
            icon={<IconAlertTriangle />}
            description="连续验证失败次数已达上限。请稍后再试，或使用其他已绑定的验证方式。"
          />
        </div>
        <div className={styles.actions}>
          <Button theme="outline" size="large" onClick={onCancel}>返回登录</Button>
        </div>
        {!isRealMode && (
          <p className={styles.notice}>当前为界面 mock，不会执行真实的多因素验证。</p>
        )}
      </div>
    );
  }

  const isSubmitting = phase.phase === "submitting";

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        {!isRealMode && <span className={styles.mockBadge}>MOCK PREVIEW</span>}
        <h1>二次验证</h1>
        <p>请完成多因素验证以继续登录。{!isRealMode && <>验证令牌：<code>{mfaToken}</code></>}</p>
      </div>

      {availableMethods.length > 1 && (
        <div className={styles.methodSelector} role="group" aria-label="选择验证方式">
          {availableMethods.map((method) => (
            <button
              key={method}
              type="button"
              className={`${styles.methodChip} ${selectedMethod === method ? styles.methodChipActive : ""}`}
              aria-pressed={selectedMethod === method}
              onClick={() => {
                setSelectedMethod(method);
                setFieldError(undefined);
              }}
            >
              {METHOD_LABELS[method]}
            </button>
          ))}
        </div>
      )}

      {selectedMethod === "totp" && (
        <form className={styles.form} method="post" onSubmit={handleTotpSubmit}>
          <label className={styles.field}>
            <span>验证器动态码</span>
            <Input
              value={codeValue}
              onChange={(nextValue) => {
                setCodeValue(nextValue.replace(/\D/g, "").slice(0, 6));
                setFieldError(undefined);
              }}
              size="large"
              prefix={<IconShield />}
              placeholder="6 位数字"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              validateStatus={fieldError ? "error" : "default"}
              aria-invalid={Boolean(fieldError)}
              aria-errormessage={fieldError ? "totp-code-error" : undefined}
              disabled={isSubmitting}
              required
            />
            <small>打开验证器应用，输入当前显示的 6 位动态验证码。</small>
            {fieldError && (
              <small id="totp-code-error" className={styles.fieldError} role="alert">
                {fieldError}
              </small>
            )}
          </label>
          <div className={styles.actions}>
            <Button theme="outline" size="large" onClick={onCancel} disabled={isSubmitting}>
              取消
            </Button>
            <Button
              htmlType="submit"
              type="primary"
              theme="solid"
              size="large"
              loading={isSubmitting}
              disabled={isSubmitting}
            >
              {isSubmitting ? "正在验证…" : isRealMode ? "验证" : "验证（Mock）"}
            </Button>
          </div>
        </form>
      )}

      {selectedMethod === "passkey" && (
        <div className={styles.form}>
          <div className={styles.field}>
            <span>通行密钥</span>
            <div className={styles.loadingBlock}>
              <IconKey size="extra-large" style={{ color: "var(--up-brand)" }} />
              <span>使用已绑定的通行密钥完成无密码验证。</span>
            </div>
          </div>
          <div className={styles.actions}>
            <Button theme="outline" size="large" onClick={onCancel} disabled={isSubmitting}>
              取消
            </Button>
            <Button
              type="primary"
              theme="solid"
              size="large"
              icon={<IconLock />}
              loading={isSubmitting}
              disabled={isSubmitting}
              onClick={handlePasskey}
            >
              {isSubmitting ? "正在验证…" : "使用通行密钥（Mock）"}
            </Button>
          </div>
        </div>
      )}

      {selectedMethod === "recovery_code" && (
        <form className={styles.form} method="post" onSubmit={handleRecoverySubmit}>
          <label className={styles.field}>
            <span>恢复代码</span>
            <Input
              value={recoveryValue}
              onChange={(nextValue) => {
                setRecoveryValue(nextValue);
                setFieldError(undefined);
              }}
              size="large"
              prefix={<IconKey />}
              placeholder="输入账户安全中心生成的恢复代码"
              autoComplete="off"
              validateStatus={fieldError ? "error" : "default"}
              aria-invalid={Boolean(fieldError)}
              aria-errormessage={fieldError ? "recovery-code-error" : undefined}
              disabled={isSubmitting}
              required
            />
            <small>恢复代码在启用二次验证时生成，每个代码仅可使用一次。</small>
            {fieldError && (
              <small id="recovery-code-error" className={styles.fieldError} role="alert">
                {fieldError}
              </small>
            )}
          </label>
          {attempts > 0 && (
            <p className={styles.attemptsNote}>
              已失败 {attempts} 次，剩余尝试次数 {MAX_ATTEMPTS - attempts} 次。
            </p>
          )}
          <div className={styles.actions}>
            <Button theme="outline" size="large" onClick={onCancel} disabled={isSubmitting}>
              取消
            </Button>
            <Button
              htmlType="submit"
              type="primary"
              theme="solid"
              size="large"
              loading={isSubmitting}
              disabled={isSubmitting}
            >
              {isSubmitting ? "正在验证…" : isRealMode ? "验证" : "验证（Mock）"}
            </Button>
          </div>
        </form>
      )}

      {!isRealMode && (
        <p className={styles.notice}>当前为界面 mock，不会执行真实的多因素验证。</p>
      )}
      {!isRealMode && (
        <div className={styles.demoLinks}>
        <p>Mock 状态演示</p>
        <ul>
          <li>
            <button
              type="button"
              className={styles.demoButton}
              onClick={() => setPhase({ phase: "expired" })}
            >
              <IconHourglass aria-hidden="true" />
              模拟挑战已过期
            </button>
          </li>
          <li>
            <button
              type="button"
              className={styles.demoButton}
              onClick={() => setPhase({ phase: "too_many_attempts" })}
            >
              <IconClose aria-hidden="true" />
              模拟尝试次数过多
            </button>
          </li>
        </ul>
        </div>
      )}
    </div>
  );
}
