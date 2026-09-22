import { createElement } from "react";
import type { ReactNode } from "react";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useRouter: () => ({ replace: vi.fn(), push: vi.fn() }) }));

vi.mock("@douyinfe/semi-ui", async () => {
  const react = await import("react");
  const passthrough = (tag: string) =>
  ({ children }: { children?: ReactNode }) => react.createElement(tag, null, children);
  return {
    Button: passthrough("button"),
    Checkbox: passthrough("label"),
    Input: () => react.createElement("input", null),
  };
});

vi.mock("@douyinfe/semi-icons", async () => {
  const react = await import("react");
  return {
    IconKey: () => react.createElement("span", null, "key"),
    IconUser: () => react.createElement("span", null, "user"),
  };
});

import { CredentialPanel } from "./credential-panel";

const sessionExpiredCopy =
  "您已经安全退出登录。为保护您的账户，长时间不活跃的登录设备会自动下线，请返回登录页重新登录。";

describe("CredentialPanel 会话失效提示", () => {
  it("会话失效时展示安全退出说明", () => {
    const html = renderToStaticMarkup(createElement(CredentialPanel, { sessionExpired: true }));

    expect(html).toContain(sessionExpiredCopy);
    expect(html).toContain('role="status"');
  });

  it("常规登录不展示安全退出说明", () => {
    const html = renderToStaticMarkup(createElement(CredentialPanel));

    expect(html).not.toContain(sessionExpiredCopy);
  });
});

describe("登录页会话失效参数", () => {
  it("把 reason=session-expired 透传给登录面板", async () => {
    const source = await readFile(
      path.join(process.cwd(), "src/app/(auth)/login/page.tsx"),
      "utf8",
    );

    expect(source).toContain('reason === "session-expired"');
    expect(source).toContain("sessionExpired={reason === \"session-expired\"}");
  });
});
