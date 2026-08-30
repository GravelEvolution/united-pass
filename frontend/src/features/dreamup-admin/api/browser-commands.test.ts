import { afterEach, describe, expect, it, vi } from "vitest";
import { dreamUPAdminCommands } from "./browser-commands";

type FetchCall = { url: string; init: RequestInit };

function stubFetch(body: unknown): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal("document", { cookie: "up_csrf=csrf-value" });
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return Response.json(body);
  }));
  return calls;
}

function headersOf(call: FetchCall): Headers {
  return new Headers(call.init.headers as HeadersInit);
}

afterEach(() => vi.unstubAllGlobals());

describe("DreamUP 管理端写操作", () => {
  it("按活动读取本人安全问题且 GET 不发送 CSRF", async () => {
    const calls = stubFetch({ state: "active", question: "安全问题？", version: 3 });

    await expect(dreamUPAdminCommands.getDashboardStepUpChallenge("event/a")).resolves.toEqual({
      state: "active",
      question: "安全问题？",
      version: 3,
    });

    expect(calls[0].url).toBe("/api/v1/admin/step-up/challenge?eventId=event%2Fa");
    expect(calls[0].init.method).toBe("GET");
    expect(headersOf(calls[0]).get("X-CSRF-Token")).toBeNull();
  });

  it("回答 active 安全问题时绑定活动看板 action 与 target", async () => {
    const calls = stubFetch({ state: "active", challengeVersion: 3 });

    await dreamUPAdminCommands.completeDashboardStepUp("event/a", {
      state: "active",
      question: "安全问题？",
      version: 3,
    }, { answer: "只用于本次验证的答案" });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/api/v1/admin/step-up/verify");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({
      eventId: "event/a",
      answer: "只用于本次验证的答案",
      action: "event.dashboard.read",
      target: "event/a",
    });
    expect(headersOf(calls[0]).get("X-CSRF-Token")).toBe("csrf-value");
    expect(headersOf(calls[0]).get("Idempotency-Key")).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("must_rotate 先按 challenge 版本轮换，再用新答案验证", async () => {
    const calls = stubFetch({ state: "active", version: 8, challengeVersion: 8 });

    await dreamUPAdminCommands.completeDashboardStepUp("event", {
      state: "must_rotate",
      question: "旧问题？",
      version: 7,
    }, {
      oldAnswer: "旧答案不会保存",
      question: "新的安全问题是什么？",
      answer: "新答案也不会保存",
    });

    expect(calls).toHaveLength(2);
    expect(calls[0].url).toBe("/api/v1/admin/step-up/rotate");
    expect(headersOf(calls[0]).get("If-Match")).toBe('"7"');
    expect(JSON.parse(String(calls[0].init.body))).toEqual({
      eventId: "event",
      oldAnswer: "旧答案不会保存",
      question: "新的安全问题是什么？",
      answer: "新答案也不会保存",
    });
    expect(calls[1].url).toBe("/api/v1/admin/step-up/verify");
    expect(JSON.parse(String(calls[1].init.body))).toMatchObject({
      answer: "新答案也不会保存",
      action: "event.dashboard.read",
      target: "event",
    });
    expect(headersOf(calls[0]).get("Idempotency-Key")).not.toBe(headersOf(calls[1]).get("Idempotency-Key"));
  });

  it("保存本人评审时发送精确活动路径、If-Match 与幂等键", async () => {
    const calls = stubFetch({ review: { recommendation: "accept", note: "值得继续", version: 1, updatedAt: 1 } });
    await dreamUPAdminCommands.saveOwnReview("event/a", "app/b", 0, {
      recommendation: "accept",
      note: "值得继续",
    });

    expect(calls[0].url).toBe("/api/v1/admin/dreamup/events/event%2Fa/applications/app%2Fb/reviews/me");
    expect(calls[0].init.method).toBe("PUT");
    expect(headersOf(calls[0]).get("If-Match")).toBe('"0"');
    expect(headersOf(calls[0]).get("Idempotency-Key")).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("投票与撤回都只能操作本管理员的录取同意", async () => {
    const consensus = { consensus: { roundId: "round_1", roundNumber: 1, status: "open", version: 3, approvalCount: 2, requiredApprovals: 3, ownApproval: true, applicationStatus: "under_review" } };
    let calls = stubFetch(consensus);
    await dreamUPAdminCommands.approveAdmission("event", "app", 2);
    expect(calls[0].init.method).toBe("PUT");
    expect(calls[0].url).toContain("/admission-consensus/approval");

    vi.unstubAllGlobals();
    calls = stubFetch(consensus);
    await dreamUPAdminCommands.withdrawAdmissionApproval("event", "app", 3);
    expect(calls[0].init.method).toBe("DELETE");
    expect(calls[0].url).toContain("/admission-consensus/approval");
  });

  it("拒绝使用独立 decision 接口并携带明确原因", async () => {
    const calls = stubFetch({ application: { ...applicationFixture, status: "rejected" } });
    await dreamUPAdminCommands.rejectApplication("event", "app", 4, "问题与本次活动方向不匹配");
    expect(calls[0].init.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ status: "rejected", reason: "问题与本次活动方向不匹配" });
    expect(headersOf(calls[0]).get("If-Match")).toBe('"4"');
  });
});

const applicationFixture = {
  id: "app",
  eventId: "event",
  displayHandle: "MOON-1",
  status: "under_review",
  version: 4,
  reviewAnswers: {},
  submittedAt: null,
  updatedAt: 1,
};
