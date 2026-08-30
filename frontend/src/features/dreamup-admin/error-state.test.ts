import { describe, expect, it } from "vitest";
import { classifyDreamUPAdminError } from "./error-state";

describe("DreamUP 管理端错误状态", () => {
  it("区分登录、权限、冲突与服务异常", () => {
    expect(classifyDreamUPAdminError({ kind: "unauthorized", message: "x" }).kind).toBe("unauthenticated");
    expect(classifyDreamUPAdminError({ kind: "forbidden", message: "x" }).kind).toBe("forbidden");
    expect(classifyDreamUPAdminError({ kind: "conflict", message: "x" }).kind).toBe("conflict");
    expect(classifyDreamUPAdminError(new Error("internal detail"))).toEqual({
      kind: "unavailable",
      message: "DreamUP 管理服务暂时不可用，请稍后重试。",
    });
  });

  it("将 DreamUP 二次验证错误保留为可恢复页面状态", () => {
    expect(classifyDreamUPAdminError({
      kind: "unauthorized",
      code: "admin_stepup.required",
      message: "请先完成管理员二次验证。",
    })).toEqual({
      kind: "step_up_required",
      message: "请先完成管理员二次验证。",
    });
  });
});
