import { describe, expect, it } from "vitest";
import {
  parseAdminStepUpChallenge,
  parseDreamUPApplicationDetail,
  parseDreamUPApplications,
  parseDreamUPEvents,
} from "./response-validators";

const application = {
  id: "app_1",
  eventId: "dreamup-shanghai-2026",
  displayHandle: "MOON-7K2P",
  status: "under_review",
  version: 4,
  reviewAnswers: {
    city: "上海",
    primary_role: "产品与硬件",
    problem_to_solve: "让设备调试更快",
  },
  submittedAt: "2026-08-16T10:00:00Z",
  updatedAt: "2026-08-17T10:00:00Z",
};

describe("DreamUP 管理端响应契约", () => {
  it("解析 active、must_rotate 与待启用 challenge，且不接收未知状态", () => {
    expect(parseAdminStepUpChallenge({
      state: "active",
      question: "你第一次独立完成的项目是什么？",
      version: 3,
      credentialVersion: 2,
    })).toEqual({ state: "active", question: "你第一次独立完成的项目是什么？", version: 3 });
    expect(parseAdminStepUpChallenge({
      state: "must_rotate",
      question: "原安全问题？",
      version: 4,
    })).toEqual({ state: "must_rotate", question: "原安全问题？", version: 4 });
    expect(parseAdminStepUpChallenge({ state: "pending_enrollment" })).toEqual({ state: "pending" });
    expect(() => parseAdminStepUpChallenge({ state: "unexpected" })).toThrow();
  });

  it("只接受当前管理员获授权的活动摘要", () => {
    expect(parseDreamUPEvents({ events: [{
      eventId: "dreamup-shanghai-2026",
      displayName: "MoonStone DreamUP 2026 上海站",
      role: "admin",
      counts: { total: 12, pending: 8, accepted: 1, rejected: 3 },
    }] })).toEqual([{ eventId: "dreamup-shanghai-2026", displayName: "MoonStone DreamUP 2026 上海站", role: "admin", counts: { total: 12, pending: 8, accepted: 1, rejected: 3 } }]);
  });

  it("解析列表和详情中的展示代号与 review-basic 答案", () => {
    expect(parseDreamUPApplications({ applications: [application] })).toEqual([application]);
    expect(parseDreamUPApplicationDetail({
      application,
      ownReview: { recommendation: "accept", note: "问题清晰", version: 2, updatedAt: "2026-08-17T11:00:00Z" },
    }).application.displayHandle).toBe("MOON-7K2P");
  });

  it.each(["email", "mobile", "photo", "identityDocument", "legalDocument", "answersJson"])(
    "拒绝包含敏感字段 %s 的基本 DTO",
    (field) => {
      expect(() => parseDreamUPApplications({
        applications: [{ ...application, [field]: "不得进入基本视图" }],
      })).toThrow();
    },
  );
});
