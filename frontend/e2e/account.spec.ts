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
