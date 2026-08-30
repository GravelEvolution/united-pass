import { createElement } from "react";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("@douyinfe/semi-ui", async () => {
  const react = await import("react");
  return {
    Banner: ({ description }: { description?: ReactNode }) => react.createElement("div", null, description),
    Button: ({ children, htmlType }: { children?: ReactNode; htmlType?: "button" | "submit" | "reset" }) => (
      react.createElement("button", { type: htmlType }, children)
    ),
    Input: ({
      id,
      name,
      mode,
      required,
      minLength,
      maxLength,
    }: {
      id?: string;
      name?: string;
      mode?: string;
      required?: boolean;
      minLength?: number;
      maxLength?: number;
    }) => react.createElement("input", {
      id,
      name,
      type: mode === "password" ? "password" : "text",
      required,
      minLength,
      maxLength,
    }),
  };
});

import { DreamUPAdminStepUpPanel } from "./dreamup-admin-step-up";

describe("DreamUP 管理员二次验证界面", () => {
  it("active challenge 只要求回答当前问题", () => {
    const html = renderToStaticMarkup(createElement(DreamUPAdminStepUpPanel, {
      eventId: "event-1",
      challenge: { state: "active", question: "你第一次独立完成的项目是什么？", version: 3 },
      onVerified: vi.fn(),
    }));

    expect(html).toContain("你第一次独立完成的项目是什么？");
    expect(html).toContain('name="answer"');
    expect(html).not.toContain('name="oldAnswer"');
    expect(html).not.toContain('name="question"');
  });

  it("must_rotate challenge 要求旧答案、新问题与新答案", () => {
    const html = renderToStaticMarkup(createElement(DreamUPAdminStepUpPanel, {
      eventId: "event-1",
      challenge: { state: "must_rotate", question: "原安全问题？", version: 7 },
      onVerified: vi.fn(),
    }));

    expect(html).toContain("原安全问题？");
    expect(html).toContain('name="oldAnswer"');
    expect(html).toContain('name="question"');
    expect(html).toContain('name="answer"');
    expect(html).toContain("更新并验证");
  });

  it("pending challenge 保持注册关闭且不显示答案表单", () => {
    const html = renderToStaticMarkup(createElement(DreamUPAdminStepUpPanel, {
      eventId: "event-1",
      challenge: { state: "pending" },
      onVerified: vi.fn(),
    }));

    expect(html).toContain("安全问题尚未启用");
    expect(html).toContain("此页面不开放注册或初始化");
    expect(html).not.toContain("<form");
  });
});
