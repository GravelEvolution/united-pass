//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Playwright end-to-end tests for the account self-service pages
//

import { test, expect } from "@playwright/test";

test.describe("账户中心流程", () => {
  test("账户页面可以正常加载", async ({ page }) => {
    await page.goto("/account");

    // 验证账户页面存在
    await expect(page.locator("h1, h2, h3").first()).toBeVisible();
  });

  test("安全设置页面可以正常加载", async ({ page }) => {
    await page.goto("/account/security");

    // 验证安全设置页面存在
    await expect(page.locator("h1, h2, h3").first()).toBeVisible();
  });

  test("Mock 通行密钥可添加删除且不会调用 WebAuthn", async ({ page }) => {
    await page.addInitScript(() => {
      const state = globalThis as unknown as { __webauthnCalls: number };
      state.__webauthnCalls = 0;
      Object.defineProperty(navigator, "credentials", {
        configurable: true,
        value: {
          create: async () => {
            state.__webauthnCalls += 1;
            throw new Error("Mock mode invoked navigator.credentials.create");
          },
          get: async () => {
            state.__webauthnCalls += 1;
            throw new Error("Mock mode invoked navigator.credentials.get");
          },
        },
      });
    });
    await page.goto("/account/security");

    await page.getByRole("button", { name: "添加" }).click();
    await page.getByLabel("当前密码").fill("mock-password");
    await page.getByRole("button", { name: "验证并开始注册" }).click();
    await expect(page.getByText("凭据标识：mock-passkey-id")).toBeVisible();

    const passkeyRow = page.locator("article").filter({ hasText: "mock-passkey-id" });
    await passkeyRow.getByRole("button", { name: "删除" }).click();
    await page.getByLabel("当前密码").fill("mock-password");
    await page.getByRole("button", { name: "验证并删除" }).click();
    await expect(page.getByText("凭据标识：mock-passkey-id")).toHaveCount(0);

    await expect.poll(async () => page.evaluate(() => (
      globalThis as unknown as { __webauthnCalls: number }
    ).__webauthnCalls)).toBe(0);
  });

  test("会话页面可以正常加载", async ({ page }) => {
    await page.goto("/account/sessions");

    // 验证会话页面存在
    await expect(page.locator("h1, h2, h3").first()).toBeVisible();
  });

  test("授权应用页面可以正常加载", async ({ page }) => {
    await page.goto("/account/applications");

    // 验证授权应用页面存在
    await expect(page.locator("h1, h2, h3").first()).toBeVisible();
  });
});
