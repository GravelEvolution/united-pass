"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import { Button, Input, Modal } from "@douyinfe/semi-ui";
import styles from "./account-panels.module.css";

export type ContactKind = "email" | "phone";

type ContactVerificationModalProps = {
  kind: ContactKind;
  currentValue: string;
  onCancel: () => void;
  onVerified: (nextValue: string) => void;
};

const MOCK_VERIFICATION_CODE = "246810";
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_PATTERN = /^\+[1-9]\d{7,14}$/;

function validateContactValue(kind: ContactKind, value: string): string | undefined {
  if (!value) return kind === "email" ? "请输入新邮箱地址。" : "请输入新手机号码。";
  if (kind === "email" && !EMAIL_PATTERN.test(value)) return "请输入有效的邮箱地址。";
  if (kind === "phone" && !PHONE_PATTERN.test(value)) return "请输入含国家代码的手机号码，例如 +8613800138000。";
  return undefined;
}

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
  const isEmail = kind === "email";
  const contactLabel = isEmail ? "邮箱地址" : "手机号码";
  const normalizedContactValue = contactValue.trim();

  function handleRequestCode(event: FormEvent<HTMLFormElement>) {
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
    setStep("verify");
  }

  function handleVerifyCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (verificationCode.trim() !== MOCK_VERIFICATION_CODE) {
      setFieldError("验证码错误，请输入页面显示的 Mock 验证码。");
      return;
    }

    onVerified(normalizedContactValue);
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
        <form className={styles.contactForm} onSubmit={handleRequestCode}>
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
              required
            />
            {fieldError && (
              <small id={`new-${kind}-error`} className={styles.profileError} role="alert">
                {fieldError}
              </small>
            )}
          </label>
          <p className={styles.profileNotice}>
            这是 Mock 验证流程，不会真的发送邮件或短信，也不会持久化联系方式。
          </p>
          <div className={styles.profileActions}>
            <Button theme="outline" onClick={onCancel}>取消</Button>
            <Button htmlType="submit" type="primary" theme="solid">发送 Mock 验证码</Button>
          </div>
        </form>
      ) : (
        <form className={styles.contactForm} onSubmit={handleVerifyCode}>
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
            }}>
              返回修改
            </Button>
            <Button htmlType="submit" type="primary" theme="solid">验证并更新</Button>
          </div>
        </form>
      )}
    </Modal>
  );
}
