//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Contact verification modal (email/SMS code)
//

"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import { Button, Input, Modal, Toast } from "@douyinfe/semi-ui";
import { validateContactValue, type ContactKind } from "../utils/contact-validation";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import styles from "./account-panels.module.css";

type ContactVerificationModalProps = {
  kind: ContactKind;
  currentValue: string;
  onCancel: () => void;
  onVerified: (nextValue: string) => void;
};

const MOCK_VERIFICATION_CODE = "246810";

export function ContactVerificationModal({
  kind,
  currentValue,
  onCancel,
  onVerified,
}: ContactVerificationModalProps) {
  const [step, setStep] = useState<"request" | "verify">("request");
  const [contactValue, setContactValue] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [fieldError, setFieldError] = useState<string>();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [requestId, setRequestId] = useState<string>();
  const isEmail = kind === "email";
  const contactLabel = isEmail ? "邮箱地址" : "手机号码";
  const normalizedContactValue = contactValue.trim();

  async function handleRequestCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const validationError = validateContactValue(kind, normalizedContactValue);

    if (validationError) {
      setFieldError(validationError);
      return;
    }

    if (normalizedContactValue === currentValue) {
      setFieldError(`新${contactLabel}不能与当前值相同。`);
      return;
    }

    setFieldError(undefined);
    setIsSubmitting(true);
    try {
      const result = isEmail
        ? await browserCommands.requestEmailChange(normalizedContactValue)
        : await browserCommands.requestPhoneChange(normalizedContactValue);
      setRequestId(result.requestId);
      setStep("verify");
    } catch {
      Toast.error({ content: `发送验证码失败，请稍后重试。` });
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleVerifyCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (verificationCode.trim() !== MOCK_VERIFICATION_CODE) {
      setFieldError("验证码错误，请输入页面显示的 Mock 验证码。");
      return;
    }

    if (!requestId) {
      setFieldError("验证请求已失效，请重新发起。");
      return;
    }

    setFieldError(undefined);
    setIsSubmitting(true);
    try {
      if (isEmail) {
        await browserCommands.verifyEmailChange(requestId, verificationCode.trim());
      } else {
        await browserCommands.verifyPhoneChange(requestId, verificationCode.trim());
      }
      onVerified(normalizedContactValue);
    } catch {
      setFieldError("验证失败，请检查验证码或稍后重试。");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Modal
      title={`修改${contactLabel}`}
      visible
      footer={null}
      width={480}
      maskClosable={false}
      onCancel={onCancel}
    >
      {step === "request" ? (
        <form className={styles.contactForm} method="post" onSubmit={handleRequestCode}>
          <p className={styles.contactCurrent}>当前{contactLabel}：<strong>{currentValue}</strong></p>
          <label className={styles.profileField} htmlFor={`new-${kind}`}>
            <span>新{contactLabel}</span>
            <Input
              id={`new-${kind}`}
              type={isEmail ? "email" : "tel"}
              value={contactValue}
              onChange={(nextValue) => {
                setContactValue(nextValue);
                setFieldError(undefined);
              }}
              placeholder={isEmail ? "new-address@example.com" : "+8613800138000"}
              autoComplete={isEmail ? "email" : "tel"}
              validateStatus={fieldError ? "error" : "default"}
              aria-invalid={Boolean(fieldError)}
              aria-errormessage={fieldError ? `new-${kind}-error` : undefined}
              disabled={isSubmitting}
              required
            />
            {fieldError && (
              <small id={`new-${kind}-error`} className={styles.profileError} role="alert">
                {fieldError}
              </small>
            )}
          </label>
          <p className={styles.profileNotice}>
            这是 Mock 验证流程，不会真的发送邮件或短信。后端接入后将通过安全渠道发送验证码。
          </p>
          <div className={styles.profileActions}>
            <Button theme="outline" onClick={onCancel} disabled={isSubmitting}>取消</Button>
            <Button htmlType="submit" type="primary" theme="solid" loading={isSubmitting} disabled={isSubmitting}>
              发送验证码
            </Button>
          </div>
        </form>
      ) : (
        <form className={styles.contactForm} method="post" onSubmit={handleVerifyCode}>
          <p className={styles.contactCurrent}>正在验证：<strong>{normalizedContactValue}</strong></p>
          <div className={styles.mockCode} aria-live="polite">
            <span>本次 Mock 验证码</span>
            <code>{MOCK_VERIFICATION_CODE}</code>
          </div>
          <label className={styles.profileField} htmlFor={`${kind}-verification-code`}>
            <span>输入验证码</span>
            <Input
              id={`${kind}-verification-code`}
              value={verificationCode}
              onChange={(nextCode) => {
                setVerificationCode(nextCode.replace(/\D/g, "").slice(0, 6));
                setFieldError(undefined);
              }}
              placeholder="6 位验证码"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              validateStatus={fieldError ? "error" : "default"}
              aria-invalid={Boolean(fieldError)}
              aria-errormessage={fieldError ? `${kind}-verification-code-error` : undefined}
              disabled={isSubmitting}
              required
            />
            {fieldError && (
              <small id={`${kind}-verification-code-error`} className={styles.profileError} role="alert">
                {fieldError}
              </small>
            )}
          </label>
          <div className={styles.profileActions}>
            <Button theme="outline" onClick={() => {
              setStep("request");
              setVerificationCode("");
              setFieldError(undefined);
              setRequestId(undefined);
            }}>
              返回修改
            </Button>
            <Button htmlType="submit" type="primary" theme="solid" loading={isSubmitting} disabled={isSubmitting}>
              验证并更新
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}
