//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Playwright end-to-end tests for the login flow
//

import { test, expect } from "@playwright/test";

test.describe("登录流程", () => {
  test("客户端脚本不可用时凭据不会进入 URL", async ({ page }) => {
    await page.goto("/login");
    const form = page.locator("form");
    await expect(form).toHaveAttribute("method", "post");

    await page.fill('input[placeholder="账户名或 name@example.com"]', "fallback-user");
    await page.fill('input[placeholder="输入密码"]', "fallback-password");

    const submission = page.waitForRequest((request) =>
      request.method() === "POST" && new URL(request.url()).pathname === "/login"
    );
    // Native submit bypasses React's submit handler and exercises the exact
    // browser fallback used before hydration or when client scripts fail.
    await form.evaluate((element) => (element as HTMLFormElement).submit());
    const request = await submission;

    expect(request.url()).not.toContain("fallback-user");
    expect(request.url()).not.toContain("fallback-password");
  });

  test("管理员可以通过密码登录并跳转到管理端", async ({ page }) => {
    await page.goto("/login");

    // 等待登录表单加载
    await expect(page.locator('input[placeholder="账户名或 name@example.com"]')).toBeVisible();

    // 填写管理员凭据
    await page.fill('input[placeholder="账户名或 name@example.com"]', "zhixing.lin");
    await page.fill('input[placeholder="输入密码"]', "MockAdmin123!");

    // 提交登录
    await page.getByRole("button", { name: /登录/ }).click();

    // 验证跳转到管理端
    await expect(page).toHaveURL(/\/admin/);
  });

  test("外部用户可以通过密码登录并跳转到账户页", async ({ page }) => {
    await page.goto("/login");

    await expect(page.locator('input[placeholder="账户名或 name@example.com"]')).toBeVisible();

    await page.fill('input[placeholder="账户名或 name@example.com"]', "app.user");
    await page.fill('input[placeholder="输入密码"]', "MockUser123!");

    await page.getByRole("button", { name: /登录/ }).click();

    await expect(page).toHaveURL(/\/account/);
  });

  test("错误凭据显示错误提示", async ({ page }) => {
    await page.goto("/login");

    await page.fill('input[placeholder="账户名或 name@example.com"]', "wrong.user");
    await page.fill('input[placeholder="输入密码"]', "WrongPassword!");

    await page.getByRole("button", { name: /登录/ }).click();

    // 验证错误提示显示
    await expect(page.getByText(/错误/)).toBeVisible();
  });

  test("授权页可以直接渲染同意界面", async ({ page }) => {
    await page.goto("/authorize?requestId=consent_demo_001");

    // 授权页应该渲染同意界面，而不是重定向到登录
    await expect(page).toHaveURL(/\/authorize/);
  });

  test("忘记密码页可以正常加载", async ({ page }) => {
    await page.goto("/forgot-password");

    // 页面应该正常加载
    await expect(page).toHaveURL(/\/forgot-password/);
  });

  test("注册页可以正常加载", async ({ page }) => {
    await page.goto("/register");

    // 页面应该正常加载
    await expect(page).toHaveURL(/\/register/);
  });
});
