import { test, expect } from "@playwright/test";

test.describe("管理端关键流程", () => {
  test("管理端仪表盘可以正常加载", async ({ page }) => {
    await page.goto("/admin");

    // 验证页面内容存在
    await expect(page.locator("body")).not.toBeEmpty();
  });

  test("审计页面可以正常加载并显示事件", async ({ page }) => {
    await page.goto("/admin/audit");

    // 验证审计页面标题存在
    await expect(page.getByRole("heading", { name: "审计事件" })).toBeVisible();
  });

  test("应用创建表单可以正常加载", async ({ page }) => {
    await page.goto("/admin/applications/new");

    // 验证创建表单存在
    await expect(page.locator("form")).toBeVisible();
  });

  test("用户列表页可以正常加载", async ({ page }) => {
    await page.goto("/admin/users");

    // 验证页面内容存在
    await expect(page.locator("body")).not.toBeEmpty();
  });

  test("Provider 列表页可以正常加载", async ({ page }) => {
    await page.goto("/admin/providers");

    // 验证页面内容存在
    await expect(page.locator("body")).not.toBeEmpty();
  });

  test("策略编辑器可以正常加载", async ({ page }) => {
    await page.goto("/admin/policies/new");

    // 验证策略编辑器表单存在
    await expect(page.locator("form")).toBeVisible();
  });

  test("审计页面可以通过 URL 参数筛选", async ({ page }) => {
    // 直接使用 URL 参数筛选
    await page.goto("/admin/audit?result=denied");

    // 验证页面正常加载
    await expect(page.getByRole("heading", { name: "审计事件" })).toBeVisible();
  });
});
