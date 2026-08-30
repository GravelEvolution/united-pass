"use client";

import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Banner, Button, Input } from "@douyinfe/semi-ui";
import { isApiError } from "@/lib/api/api-error";
import { dreamUPAdminCommands } from "../api/browser-commands";
import type { AdminStepUpChallenge } from "../types";
import styles from "./dreamup-admin.module.css";

function submittedValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === "string" ? value : "";
}

function stepUpErrorMessage(error: unknown): string {
  return isApiError(error) ? error.message : "二次验证暂时不可用，请稍后重试。";
}

export function DreamUPAdminStepUpPanel({
  eventId,
  challenge,
  onVerified,
}: {
  eventId: string;
  challenge: AdminStepUpChallenge;
  onVerified: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string>();

  if (challenge.state === "pending") {
    return (
      <section className={styles.routeState} role="status">
        <span>MoonStone DreamUP 上海站</span>
        <h1>安全问题尚未启用</h1>
        <p>你的管理员安全问题仍在等待启用。此页面不开放注册或初始化，请联系现有平台主管处理。</p>
      </section>
    );
  }
  const answerableChallenge: Exclude<AdminStepUpChallenge, { state: "pending" }> = challenge;

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    setSubmitting(true);
    setErrorMessage(undefined);
    try {
      if (answerableChallenge.state === "must_rotate") {
        await dreamUPAdminCommands.completeDashboardStepUp(eventId, answerableChallenge, {
          oldAnswer: submittedValue(formData, "oldAnswer"),
          question: submittedValue(formData, "question"),
          answer: submittedValue(formData, "answer"),
        });
      } else {
        await dreamUPAdminCommands.completeDashboardStepUp(eventId, answerableChallenge, {
          answer: submittedValue(formData, "answer"),
        });
      }
      form.reset();
      onVerified();
    } catch (error) {
      setErrorMessage(stepUpErrorMessage(error));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className={styles.routeState} aria-labelledby="dreamup-step-up-title">
      <span>MoonStone DreamUP 上海站</span>
      <h1 id="dreamup-step-up-title">
        {answerableChallenge.state === "must_rotate" ? "更新安全问题后继续" : "完成管理员二次验证"}
      </h1>
      <p>
        {answerableChallenge.state === "must_rotate"
          ? "当前安全问题必须更新。验证旧答案并设置新问题后，系统会立即用新答案完成本次验证。"
          : "回答仅用于本次管理员验证，不会保存在浏览器中。"}
      </p>
      <form className={styles.stepUpForm} method="post" onSubmit={handleSubmit}>
        <div className={styles.stepUpQuestion}>
          <span>{answerableChallenge.state === "must_rotate" ? "当前安全问题" : "安全问题"}</span>
          <strong>{answerableChallenge.question}</strong>
        </div>

        {answerableChallenge.state === "must_rotate" && (
          <>
            <label className={styles.formField} htmlFor="dreamup-step-up-old-answer">
              <span>当前答案</span>
              <Input
                id="dreamup-step-up-old-answer"
                name="oldAnswer"
                mode="password"
                autoComplete="off"
                disabled={submitting}
                required
              />
            </label>
            <label className={styles.formField} htmlFor="dreamup-step-up-question">
              <span>新安全问题</span>
              <Input
                id="dreamup-step-up-question"
                name="question"
                minLength={5}
                maxLength={200}
                disabled={submitting}
                required
              />
            </label>
          </>
        )}

        <label className={styles.formField} htmlFor="dreamup-step-up-answer">
          <span>{answerableChallenge.state === "must_rotate" ? "新答案" : "答案"}</span>
          <Input
            id="dreamup-step-up-answer"
            name="answer"
            mode="password"
            autoComplete="off"
            minLength={7}
            maxLength={256}
            disabled={submitting}
            required
          />
        </label>

        {errorMessage && (
          <Banner type="danger" fullMode={false} bordered closeIcon={null} description={errorMessage} />
        )}
        <Button block htmlType="submit" type="primary" theme="solid" loading={submitting} disabled={submitting}>
          {answerableChallenge.state === "must_rotate" ? "更新并验证" : "验证并进入看板"}
        </Button>
      </form>
    </section>
  );
}

export function DreamUPAdminStepUp({ eventId }: { eventId: string }) {
  const router = useRouter();
  const [loadState, setLoadState] = useState<
    | { status: "loading"; eventId: string }
    | { status: "ready"; eventId: string; challenge: AdminStepUpChallenge }
    | { status: "error"; eventId: string; message: string }
  >({ status: "loading", eventId });
  const [loadAttempt, setLoadAttempt] = useState(0);

  useEffect(() => {
    let ignore = false;
    void dreamUPAdminCommands.getDashboardStepUpChallenge(eventId)
      .then((nextChallenge) => {
        if (!ignore) setLoadState({ status: "ready", eventId, challenge: nextChallenge });
      })
      .catch((error: unknown) => {
        if (!ignore) setLoadState({ status: "error", eventId, message: stepUpErrorMessage(error) });
      });
    return () => {
      ignore = true;
    };
  }, [eventId, loadAttempt]);

  if (loadState.eventId !== eventId || loadState.status === "loading") {
    return (
      <section className={styles.routeState} role="status">
        <span>MoonStone DreamUP 上海站</span>
        <h1>正在读取安全问题</h1>
        <p>请稍候，不要离开此页面。</p>
      </section>
    );
  }
  if (loadState.status === "error") {
    return (
      <section className={styles.routeState} role="alert">
        <span>MoonStone DreamUP 上海站</span>
        <h1>无法读取安全问题</h1>
        <p>{loadState.message}</p>
        <Button theme="solid" type="primary" onClick={() => {
          setLoadState({ status: "loading", eventId });
          setLoadAttempt((current) => current + 1);
        }}>
          重试
        </Button>
      </section>
    );
  }
  return (
    <DreamUPAdminStepUpPanel
      eventId={eventId}
      challenge={loadState.challenge}
      onVerified={() => router.refresh()}
    />
  );
}
