import { renderToStaticMarkup } from "react-dom/server";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import RegisterPage from "./(auth)/register/page";

afterEach(() => vi.unstubAllEnvs());

describe("registration availability", () => {
  it("keeps public registration closed without rendering a credential form", async () => {
    vi.stubEnv("UP_PUBLIC_REGISTRATION_ENABLED", "false");
    const page = await RegisterPage({ searchParams: Promise.resolve({}) });
    const html = renderToStaticMarkup(page);

    expect(html).toContain("注册暂未开放");
    expect(html).toContain('href="/login"');
    expect(html).not.toMatch(/<form\b/iu);
    expect(html).not.toMatch(/<input\b/iu);
    expect(html).not.toContain("password");
  });

  it("contains the complete real form behind the server registration flag", () => {
    const pageSource = readFileSync(resolve(process.cwd(), "src/app/(auth)/register/page.tsx"), "utf8");
    const panelSource = readFileSync(resolve(process.cwd(), "src/features/auth/components/registration-panel.tsx"), "utf8");

    expect(pageSource).toContain('process.env.UP_PUBLIC_REGISTRATION_ENABLED === "true"');
    expect(panelSource).toContain("创建统一账户");
    for (const field of ["username", "displayName", "email", "password", "passwordConfirmation"]) {
      expect(panelSource).toContain(`name="${field}"`);
    }
    expect(panelSource).toContain("requestId=${encodeURIComponent(requestId)}");
    expect(panelSource).toContain("注册凭据已自动更新，请再次点击创建账户。");
  });
});
