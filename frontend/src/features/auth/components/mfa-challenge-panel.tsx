//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Real TOTP and WebAuthn login challenge panel
//

"use client";

import type { FormEvent } from "react";
import { useEffect, useRef, useState } from "react";
import { Banner, Button, Input } from "@douyinfe/semi-ui";
import {
  IconAlertTriangle,
  IconHourglass,
  IconKey,
  IconLock,
  IconShield,
} from "@douyinfe/semi-icons";
import type {
  LoginMfaMethod,
  LoginMfaVerification,
} from "@/features/auth/types";
import {
  getPasskeyAssertion,
  isWebAuthnSupported,
} from "@/features/account/utils/webauthn";
import { isApiError } from "@/lib/api/api-error";
import styles from "./credential-panel.module.css";

type MfaChallengePanelProps = {
  availableMethods: LoginMfaMethod[];
  passkeyRequestOptions?: unknown;
  expiresAt: string;
  onSuccess: () => void;
  onCancel: () => void;
  onVerify: (input: LoginMfaVerification) => Promise<void>;
};

type MfaPhase =
  | { phase: "active" }
  | { phase: "submitting" }
  | { phase: "expired" }
  | { phase: "too_many_attempts" };

const METHOD_LABELS: Record<LoginMfaMethod, string> = {
  totp: "验证器应用",
  passkey: "通行密钥",
};

function verifyErrorMessage(error: unknown): string {
  if (error instanceof DOMException && error.name === "NotAllowedError") {
    return "未完成通行密钥验证。请重试，或选择其他验证方式。";
  }
  if (isApiError(error)) return error.message;
  return "验证失败，请重试。";
}

export function MfaChallengePanel({
  availableMethods,
  passkeyRequestOptions,
  expiresAt,
  onSuccess,
  onCancel,
  onVerify,
}: MfaChallengePanelProps) {
  const [selectedMethod, setSelectedMethod] = useState<LoginMfaMethod>(
    availableMethods[0],
  );
  const [phase, setPhase] = useState<MfaPhase>({ phase: "active" });
  const [codeValue, setCodeValue] = useState("");
  const [fieldError, setFieldError] = useState<string>();
  const passkeyController = useRef<AbortController | null>(null);

  useEffect(() => {
    const remaining = Date.parse(expiresAt) - Date.now();
    const delay = Number.isFinite(remaining) && remaining > 0
      ? Math.min(remaining, 2_147_483_647)
      : 0;
    const timer = window.setTimeout(
      () => setPhase({ phase: "expired" }),
      delay,
    );
    return () => window.clearTimeout(timer);
  }, [expiresAt]);

  useEffect(() => () => passkeyController.current?.abort(), []);

  function applyVerificationError(error: unknown) {
    if (isApiError(error) && error.kind === "rate_limited") {
      setPhase({ phase: "too_many_attempts" });
      return;
    }
    if (isApiError(error) && error.code?.includes("expired")) {
      setPhase({ phase: "expired" });
      return;
    }
    setPhase({ phase: "active" });
    setFieldError(verifyErrorMessage(error));
  }

  async function handleTotpSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const code = codeValue.trim();
    if (!/^\d{6}$/.test(code)) {
      setFieldError("请输入 6 位数字验证码。");
      return;
    }
    setPhase({ phase: "submitting" });
    setFieldError(undefined);
    try {
      await onVerify({ method: "totp", code });
      onSuccess();
    } catch (error) {
      applyVerificationError(error);
    }
  }

  async function handlePasskey() {
    if (passkeyRequestOptions === undefined) {
      setFieldError("服务端未返回通行密钥挑战，请返回登录后重试。");
      return;
    }
    if (!isWebAuthnSupported()) {
      setFieldError("当前浏览器不支持通行密钥，请使用受支持的浏览器或选择验证器应用。");
      return;
    }
    passkeyController.current?.abort();
    const controller = new AbortController();
    passkeyController.current = controller;
    setPhase({ phase: "submitting" });
    setFieldError(undefined);
    try {
      const passkeyAssertion = await getPasskeyAssertion(
        passkeyRequestOptions,
        controller.signal,
      );
      await onVerify({ method: "passkey", passkeyAssertion });
      onSuccess();
    } catch (error) {
      if (controller.signal.aborted) return;
      applyVerificationError(error);
    } finally {
      if (passkeyController.current === controller) {
        passkeyController.current = null;
      }
    }
  }

  function cancel() {
    passkeyController.current?.abort();
    onCancel();
  }

  if (phase.phase === "expired" || phase.phase === "too_many_attempts") {
    const expired = phase.phase === "expired";
    return (
      <div className={styles.panel}>
        <div className={styles.heading}>
          <h1>{expired ? "验证已过期" : "尝试次数过多"}</h1>
          <p>
            {expired
              ? "多因素验证挑战已超时，请返回登录重新发起。"
              : "为保护账户安全，多因素验证已被暂时限制。"}
          </p>
        </div>
        <div role="alert">
          <Banner
            type={expired ? "warning" : "danger"}
            icon={expired ? <IconHourglass /> : <IconAlertTriangle />}
            description={expired
              ? "出于安全考虑，验证挑战有效时间较短。请重新登录以获取新的验证挑战。"
              : "请求频率已达上限，请按服务端提示稍后重新登录。"}
          />
        </div>
        <div className={styles.actions}>
          <Button theme="outline" size="large" onClick={cancel}>返回登录</Button>
        </div>
      </div>
    );
  }

  const isSubmitting = phase.phase === "submitting";

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <h1>二次验证</h1>
        <p>请使用账户已绑定的安全方式继续登录。</p>
      </div>

      {availableMethods.length > 1 && (
        <div className={styles.methodSelector} role="group" aria-label="选择验证方式">
          {availableMethods.map((method) => (
            <button
              key={method}
              type="button"
              className={`${styles.methodChip} ${selectedMethod === method ? styles.methodChipActive : ""}`}
              aria-pressed={selectedMethod === method}
              disabled={isSubmitting}
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
              aria-errormessage={fieldError ? "mfa-error" : undefined}
              disabled={isSubmitting}
              required
            />
            <small>打开验证器应用，输入当前显示的 6 位动态验证码。</small>
            {fieldError && <small id="mfa-error" className={styles.fieldError} role="alert">{fieldError}</small>}
          </label>
          <div className={styles.actions}>
            <Button theme="outline" size="large" onClick={cancel} disabled={isSubmitting}>取消</Button>
            <Button htmlType="submit" type="primary" theme="solid" size="large" loading={isSubmitting} disabled={isSubmitting}>
              {isSubmitting ? "正在验证…" : "验证"}
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
              <span>通过系统安全提示，使用已绑定的通行密钥完成验证。</span>
            </div>
            {fieldError && <small id="mfa-error" className={styles.fieldError} role="alert">{fieldError}</small>}
          </div>
          <div className={styles.actions}>
            <Button theme="outline" size="large" onClick={cancel} disabled={isSubmitting}>取消</Button>
            <Button type="primary" theme="solid" size="large" icon={<IconLock />} loading={isSubmitting} disabled={isSubmitting} onClick={() => void handlePasskey()}>
              {isSubmitting ? "正在验证…" : "使用通行密钥"}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
