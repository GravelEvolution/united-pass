import { createElement } from "react";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useRouter: () => ({ replace: vi.fn() }) }));
vi.mock("next/image", async () => {
  const react = await import("react");
  return { default: ({ alt }: { alt: string }) => react.createElement("img", { alt }) };
});
vi.mock("@douyinfe/semi-ui", async () => {
  const react = await import("react");
  return {
    Button: ({ children }: { children?: ReactNode }) => react.createElement("button", null, children),
    Spin: () => react.createElement("span", null, "loading"),
  };
});

import { QrLoginPanel } from "./qr-login-panel";
import { createQRLoginPoller, parseQRLoginChallenge, parseQRLoginConsumeResult } from "./qr-login-polling";

afterEach(() => vi.useRealTimers());

describe("QR 登录组件", () => {
  it("初始状态只提供显式生成操作并说明接收方凭据不会进入二维码", () => {
    const html = renderToStaticMarkup(createElement(QrLoginPanel));
    expect(html).toContain("生成安全登录码");
    expect(html).toContain("二维码不包含账户、会话或接收方凭据");
    expect(html).not.toContain("等待小程序确认");
  });

  it("严格收窄 challenge 与 consume 响应", () => {
    expect(parseQRLoginChallenge({ challengeId: "A".repeat(20), expiresInSeconds: 1 })).toEqual({
      challengeId: "A".repeat(20),
      expiresInSeconds: 1,
    });
    expect(parseQRLoginConsumeResult({ status: "pending" })).toEqual({ status: "pending" });
    expect(parseQRLoginConsumeResult({ status: "authenticated", csrfToken: "csrf-token" })).toEqual({
      status: "authenticated",
      csrfToken: "csrf-token",
    });
    expect(() => parseQRLoginChallenge({ challengeId: "A".repeat(20), expiresInSeconds: 601 })).toThrow();
    expect(() => parseQRLoginConsumeResult({ status: "authenticated" })).toThrow();
    expect(() => parseQRLoginConsumeResult({ status: "pending", extra: true })).toThrow();
  });

  it("pending 后继续轮询，并在 authenticated 时停止", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-27T00:00:00Z"));
    const consume = vi.fn()
      .mockResolvedValueOnce({ status: "pending" })
      .mockResolvedValueOnce({ status: "authenticated", csrfToken: "csrf-token" });
    const onAuthenticated = vi.fn();
    const poller = createQRLoginPoller({
      challenge: { challengeId: "B".repeat(20), expiresInSeconds: 120 },
      consume,
      onAuthenticated,
      onExpired: vi.fn(),
      onError: vi.fn(),
      onRemainingSeconds: vi.fn(),
    });

    await poller.start();
    await vi.advanceTimersByTimeAsync(1_500);
    expect(consume).toHaveBeenCalledTimes(2);
    expect(onAuthenticated).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(3_000);
    expect(consume).toHaveBeenCalledTimes(2);
  });

  it("瞬时错误使用有上限退避继续轮询", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-27T00:00:00Z"));
    const transient = new TypeError("network");
    const consume = vi.fn()
      .mockRejectedValueOnce(transient)
      .mockRejectedValueOnce(transient)
      .mockResolvedValueOnce({ status: "authenticated", csrfToken: "csrf-token" });
    const onRetry = vi.fn();
    const onError = vi.fn();
    const onAuthenticated = vi.fn();
    const poller = createQRLoginPoller({
      challenge: { challengeId: "C".repeat(20), expiresInSeconds: 120 },
      consume,
      onAuthenticated,
      onExpired: vi.fn(),
      onError,
      onRetry,
      isRetryableError: () => true,
      random: () => 0.5,
      onRemainingSeconds: vi.fn(),
    });

    await poller.start();
    expect(onRetry).toHaveBeenLastCalledWith(transient, 1_500, 1);
    await vi.advanceTimersByTimeAsync(1_500);
    expect(onRetry).toHaveBeenLastCalledWith(transient, 3_000, 2);
    await vi.advanceTimersByTimeAsync(3_000);
    expect(onAuthenticated).toHaveBeenCalledTimes(1);
    expect(onError).not.toHaveBeenCalled();
  });

  it("连续错误达到上限或响应契约错误时停止", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-27T00:00:00Z"));
    const consume = vi.fn().mockRejectedValue(new TypeError("network"));
    const onError = vi.fn();
    const poller = createQRLoginPoller({
      challenge: { challengeId: "D".repeat(20), expiresInSeconds: 120 },
      consume,
      onAuthenticated: vi.fn(),
      onExpired: vi.fn(),
      onError,
      isRetryableError: () => true,
      maxTransientFailures: 2,
      jitterRatio: 0,
      onRemainingSeconds: vi.fn(),
    });
    await poller.start();
    await vi.advanceTimersByTimeAsync(1_500);
    await vi.advanceTimersByTimeAsync(3_000);
    expect(consume).toHaveBeenCalledTimes(3);
    expect(onError).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(consume).toHaveBeenCalledTimes(3);

    const malformedError = vi.fn();
    const malformed = createQRLoginPoller({
      challenge: { challengeId: "E".repeat(20), expiresInSeconds: 120 },
      consume: vi.fn().mockResolvedValue({ status: "pending", extra: true }),
      onAuthenticated: vi.fn(),
      onExpired: vi.fn(),
      onError: malformedError,
      onRemainingSeconds: vi.fn(),
    });
    await malformed.start();
    expect(malformedError).toHaveBeenCalledTimes(1);
  });

  it("到期与卸载都会停止后续请求", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-27T00:00:00Z"));
    const expiredConsume = vi.fn().mockResolvedValue({ status: "pending" });
    const onExpired = vi.fn();
    const expiring = createQRLoginPoller({
      challenge: { challengeId: "F".repeat(20), expiresInSeconds: 1 },
      consume: expiredConsume,
      onAuthenticated: vi.fn(),
      onExpired,
      onError: vi.fn(),
      onRemainingSeconds: vi.fn(),
    });
    await expiring.start();
    await vi.advanceTimersByTimeAsync(1_500);
    expect(expiredConsume).toHaveBeenCalledTimes(1);
    expect(onExpired).toHaveBeenCalledTimes(1);

    const cancelledConsume = vi.fn().mockResolvedValue({ status: "pending" });
    const cancelled = createQRLoginPoller({
      challenge: { challengeId: "G".repeat(20), expiresInSeconds: 120 },
      consume: cancelledConsume,
      onAuthenticated: vi.fn(),
      onExpired: vi.fn(),
      onError: vi.fn(),
      onRemainingSeconds: vi.fn(),
    });
    await cancelled.start();
    cancelled.stop();
    await vi.advanceTimersByTimeAsync(3_000);
    expect(cancelledConsume).toHaveBeenCalledTimes(1);
  });
});
