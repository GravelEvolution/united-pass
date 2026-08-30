"use client";

import type { FormEvent, PropsWithChildren } from "react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Banner, Button, Input, Modal, Spin } from "@douyinfe/semi-ui";
import { IconKey, IconShield } from "@douyinfe/semi-icons";
import type { ReauthenticationAction, ReauthenticationChallenge } from "@/features/account/types";
import type { MfaMethod } from "@/features/auth/types";
import { isApiError, type StepUpChallenge } from "@/lib/api/api-error";
import { completeLoginMfa } from "@/lib/api/browser/auth-commands";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { getInteractiveCaptchaAdapter } from "@/lib/security/interactive-captcha-adapter";
import {
  registerRiskStepUpHandler,
  RiskStepUpCancelledError,
  RiskStepUpUnavailableError,
  type RiskStepUpResolution,
} from "@/lib/security/risk-step-up-runtime";
import styles from "./risk-step-up-provider.module.css";

type PendingStepUp = {
  id: number;
  challenge: StepUpChallenge;
  signal?: AbortSignal;
  abortListener?: () => void;
  resolve: (resolution: RiskStepUpResolution) => void;
  reject: (error: unknown) => void;
};

type ReauthenticationContext = {
  action: ReauthenticationAction;
  target: string;
  applicationId?: string;
  clientId?: string;
};

const REAUTHENTICATION_ACTIONS: ReadonlySet<string> = new Set<ReauthenticationAction>([
  "account.password.change",
  "account.totp.enroll",
  "account.totp.remove",
  "account.passkey.enroll",
  "account.passkey.remove",
  "account.data_export",
  "account.delete",
  "user.disable",
  "user.sessions.revoke",
  "employee.offboard",
  "provider.enable",
  "provider.disable",
  "provider.identity.link",
  "policy.publish",
  "audit.export",
  "application.delete",
  "client.delete",
  "client.secret.rotate",
]);

export function RiskStepUpProvider({ children }: PropsWithChildren) {
  const [active, setActive] = useState<PendingStepUp>();
  const activeRef = useRef<PendingStepUp | undefined>(undefined);
  const queueRef = useRef<PendingStepUp[]>([]);
  const sequenceRef = useRef(0);
  const settleRef = useRef<(
    resolution?: RiskStepUpResolution,
    error?: unknown,
  ) => void>(() => undefined);

  useEffect(() => {
    let disposed = false;
    const queue = queueRef.current;

    const showNext = () => {
      if (disposed || activeRef.current !== undefined) return;
      const next = queue.shift();
      if (!next) return;
      activeRef.current = next;
      setActive(next);
    };

    const settle = (resolution?: RiskStepUpResolution, error?: unknown) => {
      const pending = activeRef.current;
      if (!pending) return;
      if (pending.abortListener) {
        pending.signal?.removeEventListener("abort", pending.abortListener);
      }
      activeRef.current = undefined;
      setActive(undefined);
      if (error !== undefined) pending.reject(error);
      else if (resolution !== undefined) pending.resolve(resolution);
      queueMicrotask(showNext);
    };
    settleRef.current = settle;

    const unregister = registerRiskStepUpHandler((challenge, signal) =>
      new Promise<RiskStepUpResolution>((resolve, reject) => {
        if (signal?.aborted) {
          reject(signal.reason);
          return;
        }
        const pending: PendingStepUp = {
          id: sequenceRef.current += 1,
          challenge,
          signal,
          resolve,
          reject,
        };
        if (signal) {
          pending.abortListener = () => {
            if (activeRef.current?.id === pending.id) {
              settle(undefined, signal.reason);
              return;
            }
            const queuedIndex = queue.findIndex((queued) => queued.id === pending.id);
            if (queuedIndex >= 0) queue.splice(queuedIndex, 1);
            reject(signal.reason);
          };
          signal.addEventListener("abort", pending.abortListener, { once: true });
        }
        queue.push(pending);
        showNext();
      }));

    return () => {
      disposed = true;
      unregister();
      const unavailable = new RiskStepUpUnavailableError();
      const pending = activeRef.current;
      activeRef.current = undefined;
      if (pending) pending.reject(unavailable);
      queue.splice(0).forEach((queued) => queued.reject(unavailable));
    };
  }, []);

  const cancel = useCallback(() => {
    settleRef.current(undefined, new RiskStepUpCancelledError());
  }, []);

  return (
    <>
      {children}
      {active && (
        <RiskStepUpModal
          key={active.id}
          challenge={active.challenge}
          onCancel={cancel}
          onComplete={(resolution) => settleRef.current(resolution)}
        />
      )}
    </>
  );
}

type RiskStepUpModalProps = {
  challenge: StepUpChallenge;
  onCancel: () => void;
  onComplete: (resolution: RiskStepUpResolution) => void;
};

function RiskStepUpModal({ challenge, onCancel, onComplete }: RiskStepUpModalProps) {
  return (
    <Modal
      title="完成安全验证"
      visible
      footer={null}
      width={480}
      maskClosable={false}
      onCancel={onCancel}
    >
      {challenge.method === "interactive_captcha" && (
        <InteractiveCaptchaChallenge
          challenge={challenge}
          onCancel={onCancel}
          onComplete={onComplete}
        />
      )}
      {challenge.method === "mfa" && (
        <LoginMfaStepUp
          challenge={challenge}
          onCancel={onCancel}
          onComplete={onComplete}
        />
      )}
      {challenge.method === "reauth" && (
        <ReauthenticationStepUp
          challenge={challenge}
          onCancel={onCancel}
          onComplete={onComplete}
        />
      )}
      {challenge.method === "automation_cost" && (
        <div className={styles.status} role="status">
          <Spin size="large" />
          <p>正在完成后台安全检查，请稍候…</p>
        </div>
      )}
    </Modal>
  );
}

function InteractiveCaptchaChallenge({
  challenge,
  onCancel,
  onComplete,
}: RiskStepUpModalProps & { challenge: Extract<StepUpChallenge, { method: "interactive_captcha" }> }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [adapterAttempt, setAdapterAttempt] = useState(0);
  const [isRunning, setIsRunning] = useState(false);
  const [adapterError, setAdapterError] = useState<string>();
  const adapter = getInteractiveCaptchaAdapter();

  useEffect(() => {
    if (!challenge.providerReady || !adapter || !containerRef.current) return;
    const controller = new AbortController();
    setIsRunning(true);
    setAdapterError(undefined);
    void adapter.execute({
      provider: challenge.provider,
      providerPayload: challenge.providerPayload,
      container: containerRef.current,
      signal: controller.signal,
    }).then((providerProof) => {
      if (controller.signal.aborted) return;
      if (providerProof.length === 0 || providerProof.length > 8192) {
        throw new Error("provider proof shape invalid");
      }
      onComplete({ status: "provider_proof", providerProof });
    }).catch(() => {
      if (!controller.signal.aborted) {
        setAdapterError("互动验证没有完成，请重新验证。")
        setIsRunning(false);
      }
    });
    return () => controller.abort();
  }, [adapter, adapterAttempt, challenge, onComplete]);

  const unavailableMessage = !challenge.providerReady
    ? "互动验证服务尚未启用，本次请求无法继续。请稍后重试。"
    : !adapter
      ? "互动验证组件尚未配置，本次请求无法继续。请联系管理员。"
      : undefined;

  return (
    <div className={styles.content}>
      <div className={styles.introduction}>
        <IconShield size="extra-large" aria-hidden="true" />
        <div>
          <h2>检测到异常请求</h2>
          <p>请完成一次互动验证。验证结果只用于本次安全检查。</p>
        </div>
      </div>
      {unavailableMessage && (
        <Banner type="warning" fullMode={false} bordered description={unavailableMessage} />
      )}
      {adapterError && (
        <Banner type="danger" fullMode={false} bordered description={adapterError} />
      )}
      <div
        ref={containerRef}
        className={styles.captchaContainer}
        aria-label="互动安全验证"
        aria-busy={isRunning}
      >
        {isRunning && <Spin tip="正在加载验证…" />}
      </div>
      <div className={styles.actions}>
        <Button theme="outline" onClick={onCancel}>取消</Button>
        {adapterError && (
          <Button
            type="primary"
            theme="solid"
            onClick={() => setAdapterAttempt((attempt) => attempt + 1)}
          >
            重新验证
          </Button>
        )}
      </div>
    </div>
  );
}

function LoginMfaStepUp({ challenge, onCancel, onComplete }: RiskStepUpModalProps) {
  const mfaContext = parseMfaContext(challenge.providerPayload);
  const [code, setCode] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!mfaContext) return;
    setIsSubmitting(true);
    setError(undefined);
    try {
      await completeLoginMfa({ mfaToken: mfaContext.mfaToken, method: "totp", code });
      onComplete({ status: "completed" });
    } catch (submitError) {
      setError(userFacingError(submitError, "多因素验证失败，请重试。"));
    } finally {
      setIsSubmitting(false);
    }
  }

  if (!mfaContext) {
    return <UnavailableAccountStepUp message="多因素验证信息不完整，请重新登录后再试。" onCancel={onCancel} />;
  }

  return (
    <form className={styles.content} method="post" onSubmit={(event) => void submit(event)}>
      <p className={styles.lede}>输入验证器应用当前显示的 6 位动态验证码。</p>
      <label className={styles.field} htmlFor="risk-step-up-totp">
        <span>动态验证码</span>
        <Input
          id="risk-step-up-totp"
          value={code}
          onChange={(value) => {
            setCode(value.replace(/\D/g, "").slice(0, 6));
            setError(undefined);
          }}
          prefix={<IconShield />}
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          validateStatus={error ? "error" : "default"}
          aria-invalid={Boolean(error)}
          disabled={isSubmitting}
          autoFocus
        />
      </label>
      {error && <small className={styles.error} role="alert">{error}</small>}
      <div className={styles.actions}>
        <Button theme="outline" onClick={onCancel} disabled={isSubmitting}>取消</Button>
        <Button htmlType="submit" type="primary" theme="solid" loading={isSubmitting} disabled={code.length !== 6}>
          验证并继续
        </Button>
      </div>
    </form>
  );
}

function ReauthenticationStepUp({ challenge, onCancel, onComplete }: RiskStepUpModalProps) {
  const context = parseReauthenticationContext(challenge.providerPayload);
  const [password, setPassword] = useState("");
  const [mfaChallenge, setMfaChallenge] = useState<ReauthenticationChallenge>();
  const [totpCode, setTotpCode] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string>();

  async function submitPassword(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!context) return;
    setIsSubmitting(true);
    setError(undefined);
    try {
      const outcome = await browserCommands.requestReauthentication({
        action: context.action,
        target: context.target,
        applicationId: context.applicationId,
        clientId: context.clientId,
        password,
      });
      setPassword("");
      if (outcome.status === "granted") {
        onComplete({ status: "reauth_granted", reauthToken: outcome.reauthToken });
        return;
      }
      if (!outcome.availableMethods.includes("totp")) {
        setError("该账户需要使用当前页面暂不支持的验证方式，请前往账户安全中心完成验证。")
        return;
      }
      setMfaChallenge(outcome);
    } catch (submitError) {
      setError(userFacingError(submitError, "身份重新验证失败，请重试。"));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function submitTotp(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!mfaChallenge) return;
    setIsSubmitting(true);
    setError(undefined);
    try {
      const grant = await browserCommands.completeReauthenticationMfa({
        reauthToken: mfaChallenge.reauthToken,
        method: "totp",
        code: totpCode,
      });
      onComplete({ status: "reauth_granted", reauthToken: grant.reauthToken });
    } catch (submitError) {
      setError(userFacingError(submitError, "二次验证失败，请重试。"));
    } finally {
      setIsSubmitting(false);
    }
  }

  if (!context) {
    return <UnavailableAccountStepUp message="身份重新验证信息不完整，请刷新页面后再试。" onCancel={onCancel} />;
  }

  if (mfaChallenge) {
    return (
      <form className={styles.content} method="post" onSubmit={(event) => void submitTotp(event)}>
        <p className={styles.lede}>密码已确认。请输入验证器应用中的动态验证码。</p>
        <label className={styles.field} htmlFor="risk-reauth-totp">
          <span>动态验证码</span>
          <Input
            id="risk-reauth-totp"
            value={totpCode}
            onChange={(value) => {
              setTotpCode(value.replace(/\D/g, "").slice(0, 8));
              setError(undefined);
            }}
            prefix={<IconShield />}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={8}
            validateStatus={error ? "error" : "default"}
            disabled={isSubmitting}
            autoFocus
          />
        </label>
        {error && <small className={styles.error} role="alert">{error}</small>}
        <div className={styles.actions}>
          <Button theme="outline" onClick={onCancel} disabled={isSubmitting}>取消</Button>
          <Button htmlType="submit" type="primary" theme="solid" loading={isSubmitting} disabled={totpCode.length === 0}>
            验证并继续
          </Button>
        </div>
      </form>
    );
  }

  return (
    <form className={styles.content} method="post" onSubmit={(event) => void submitPassword(event)}>
      <p className={styles.lede}>这是敏感操作。请重新输入当前账户密码。</p>
      <label className={styles.field} htmlFor="risk-reauth-password">
        <span>当前密码</span>
        <Input
          id="risk-reauth-password"
          mode="password"
          value={password}
          onChange={(value) => {
            setPassword(value);
            setError(undefined);
          }}
          prefix={<IconKey />}
          autoComplete="current-password"
          validateStatus={error ? "error" : "default"}
          disabled={isSubmitting}
          required
          autoFocus
        />
      </label>
      <p className={styles.privacyNote}>密码只会发送到同源统一账户接口，不会保存在网页中。</p>
      {error && <small className={styles.error} role="alert">{error}</small>}
      <div className={styles.actions}>
        <Button theme="outline" onClick={onCancel} disabled={isSubmitting}>取消</Button>
        <Button htmlType="submit" type="primary" theme="solid" loading={isSubmitting} disabled={password.length === 0}>
          重新验证
        </Button>
      </div>
    </form>
  );
}

function UnavailableAccountStepUp({ message, onCancel }: { message: string; onCancel: () => void }) {
  return (
    <div className={styles.content}>
      <Banner type="warning" fullMode={false} bordered description={message} />
      <div className={styles.actions}>
        <Button type="primary" theme="solid" onClick={onCancel}>返回</Button>
      </div>
    </div>
  );
}

function parseMfaContext(payload: Readonly<Record<string, unknown>> | undefined): {
  mfaToken: string;
  methods: MfaMethod[];
} | undefined {
  if (!payload || typeof payload.mfaToken !== "string" || !Array.isArray(payload.availableMethods)) {
    return undefined;
  }
  const methods = payload.availableMethods.filter((method): method is MfaMethod =>
    method === "totp" || method === "passkey" || method === "recovery_code");
  if (payload.mfaToken.length === 0 || !methods.includes("totp")) return undefined;
  return { mfaToken: payload.mfaToken, methods };
}

function parseReauthenticationContext(
  payload: Readonly<Record<string, unknown>> | undefined,
): ReauthenticationContext | undefined {
  if (!payload || typeof payload.action !== "string" || !REAUTHENTICATION_ACTIONS.has(payload.action)) {
    return undefined;
  }
  if (payload.target !== undefined && typeof payload.target !== "string") return undefined;
  if (payload.applicationId !== undefined && typeof payload.applicationId !== "string") return undefined;
  if (payload.clientId !== undefined && typeof payload.clientId !== "string") return undefined;

  const applicationId = typeof payload.applicationId === "string" ? payload.applicationId : undefined;
  const clientId = typeof payload.clientId === "string" ? payload.clientId : undefined;
  if (payload.action === "application.delete" && !applicationId) return undefined;
  if (
    (payload.action === "client.delete" || payload.action === "client.secret.rotate")
    && (!applicationId || !clientId)
  ) return undefined;
  return {
    action: payload.action as ReauthenticationAction,
    target: typeof payload.target === "string" ? payload.target : "",
    applicationId,
    clientId,
  };
}

function userFacingError(error: unknown, fallback: string): string {
  return isApiError(error) ? error.message : fallback;
}
