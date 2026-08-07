//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Unit tests for consent completion flights and failure classes
//

import { describe, expect, it } from "vitest";
import {
  acquireCompletionFlight,
  classifyCompletionFailure,
  evictCompletionFlight,
} from "./consent-completion";

describe("classifyCompletionFailure", () => {
  it("classifies a 401 session failure as recoverable relogin", () => {
    expect(classifyCompletionFailure({ kind: "unauthorized", message: "会话凭据缺失" })).toEqual({
      outcome: "relogin",
    });
  });

  it("classifies conflicts, server errors and unknown errors as terminal", () => {
    expect(classifyCompletionFailure({ kind: "conflict", message: "已完成" }).outcome).toBe(
      "terminal",
    );
    expect(classifyCompletionFailure({ kind: "network", message: "网络错误" }).outcome).toBe(
      "terminal",
    );
    expect(classifyCompletionFailure(new Error("provider unavailable")).outcome).toBe("terminal");
    expect(classifyCompletionFailure("unexpected").outcome).toBe("terminal");
  });
});

describe("completion flight retention", () => {
  it("keeps a single in-flight Promise across concurrent acquires (StrictMode)", async () => {
    const calls: string[] = [];
    const decide = (requestId: string) => {
      calls.push(requestId);
      return Promise.resolve({ redirectUrl: "https://client.example/cb" });
    };

    const first = acquireCompletionFlight("req_single_flight", decide);
    const second = acquireCompletionFlight("req_single_flight", decide);

    expect(second).toBe(first);
    await expect(first).resolves.toEqual({ redirectUrl: "https://client.example/cb" });
    expect(calls).toEqual(["req_single_flight"]);

    // A resolved flight stays forever: remounts attach, never re-POST.
    const remount = acquireCompletionFlight("req_single_flight", decide);
    expect(remount).toBe(first);
    await remount;
    expect(calls).toEqual(["req_single_flight"]);
  });

  it("evicts a relogin failure so a remount may POST again after login", async () => {
    const calls: string[] = [];
    const decide = (requestId: string) => {
      calls.push(requestId);
      return Promise.reject({ kind: "unauthorized", message: "会话凭据缺失" });
    };

    const first = acquireCompletionFlight("req_relogin", decide);
    const error = await first.catch((value: unknown) => value);
    const failure = classifyCompletionFailure(error);
    expect(failure.outcome).toBe("relogin");
    // The component evicts exactly on relogin failures.
    if (failure.outcome === "relogin") {
      evictCompletionFlight("req_relogin");
    }

    // User logs in, /authorize remounts: a fresh POST may proceed.
    const second = acquireCompletionFlight("req_relogin", decide);
    expect(second).not.toBe(first);
    await second.catch(() => undefined);
    expect(calls).toEqual(["req_relogin", "req_relogin"]);
  });

  it("retains a terminal failure so a remount must NOT POST again", async () => {
    const calls: string[] = [];
    const decide = (requestId: string) => {
      calls.push(requestId);
      return Promise.reject({ kind: "conflict", message: "请求已完成" });
    };

    const first = acquireCompletionFlight("req_terminal", decide);
    const error = await first.catch((value: unknown) => value);
    const failure = classifyCompletionFailure(error);
    expect(failure.outcome).toBe("terminal");
    // No eviction for terminal failures.

    // Remount attaches to the retained rejected flight; no second POST.
    const second = acquireCompletionFlight("req_terminal", decide);
    expect(second).toBe(first);
    await second.catch(() => undefined);
    expect(calls).toEqual(["req_terminal"]);
  });
});
