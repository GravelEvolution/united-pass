"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Image from "next/image";
import { Button, Spin } from "@douyinfe/semi-ui";
import QRCode from "qrcode";
import { browserFetch } from "@/lib/api/browser/browser-http-client";
import { isApiError } from "@/lib/api/api-error";
import {
  createQRLoginPoller,
  parseQRLoginChallenge,
  type QRLoginChallenge,
} from "./qr-login-polling";
import styles from "./qr-login-panel.module.css";

function isRetryableConsumeError(reason: unknown): boolean {
  if (!isApiError(reason)) return reason instanceof TypeError;
  return reason.kind === "network" || reason.kind === "rate_limited" || reason.kind === "server_error";
}

/**
 * Browser-side half of the QR login handshake. The QR contains only a random
 * challenge ID. The receiver proof stays in the HttpOnly cookie set when the
 * challenge is created and is never rendered or read by this code.
 */
export function QrLoginPanel() {
  const router = useRouter();
  const [challenge, setChallenge] = useState<QRLoginChallenge>();
  const [qrImage, setQrImage] = useState<string>();
  const [error, setError] = useState<string>();
  const [creating, setCreating] = useState(false);
  const [remainingSeconds, setRemainingSeconds] = useState(0);

  useEffect(() => {
    if (!challenge) return;
    const poller = createQRLoginPoller({
      challenge,
      consume: (signal) => browserFetch<unknown>(`/auth/qr/challenges/${encodeURIComponent(challenge.challengeId)}/consume`, {
        method: "POST",
        signal,
      }),
      onRemainingSeconds: setRemainingSeconds,
      onAuthenticated: () => router.replace("/account"),
      onExpired: () => setError("登录码已过期，请生成新的登录码。"),
      onRetry: (_reason, delayMs) => setError(`网络有波动，将在 ${Math.max(1, Math.ceil(delayMs / 1_000))} 秒后自动重试。`),
      isRetryableError: isRetryableConsumeError,
      onError: (reason) => {
        setError(isApiError(reason) && reason.kind === "not_found"
          ? "登录码无效或已被使用，请生成新的登录码。"
          : "登录状态暂时不可用，请生成新的登录码后重试。");
      },
    });
    void poller.start();
    return () => poller.stop();
  }, [challenge, router]);

  async function createChallenge() {
    setCreating(true);
    setError(undefined);
    setChallenge(undefined);
    setQrImage(undefined);
    try {
      const created = parseQRLoginChallenge(await browserFetch<unknown>("/auth/qr/challenges", { method: "POST" }));
      const image = await QRCode.toDataURL(created.challengeId, { errorCorrectionLevel: "M", margin: 2, width: 300 });
      setQrImage(image);
      setChallenge(created);
      setRemainingSeconds(created.expiresInSeconds);
    } catch (reason) {
      setError(isApiError(reason) ? reason.message : "无法生成安全登录码，请稍后重试。");
    } finally {
      setCreating(false);
    }
  }

  return <section className={styles.panel} aria-labelledby="qr-login-title">
    <div className={styles.heading}>
      <h1 id="qr-login-title">扫码登录</h1>
      <p>使用已登录的 MoonStone DreamUP 小程序扫描并确认。二维码不包含账户、会话或接收方凭据。</p>
    </div>
    {!challenge && <Button type="primary" theme="solid" size="large" block loading={creating} disabled={creating} onClick={() => { void createChallenge(); }}>生成安全登录码</Button>}
    {challenge && qrImage && <div className={styles.challenge}>
      <Image className={styles.qr} src={qrImage} alt="用于统一门户登录确认的二维码" width={300} height={300} unoptimized />
      <div className={styles.status}><Spin size="small" /><span>等待小程序确认（约 {remainingSeconds} 秒）</span></div>
      <p>请核对浏览器地址后再扫码。确认后，本页面只会建立当前浏览器的会话。</p>
      <Button theme="borderless" type="tertiary" onClick={() => { void createChallenge(); }}>生成新的登录码</Button>
    </div>}
    {error && <p className={styles.error} role="alert">{error}</p>}
  </section>;
}
