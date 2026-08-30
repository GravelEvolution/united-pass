import { isApiError } from "@/lib/api/api-error";

export type DreamUPAdminErrorState = {
  kind: "unauthenticated" | "step_up_required" | "forbidden" | "not_found" | "conflict" | "unavailable";
  message: string;
};

export function classifyDreamUPAdminError(error: unknown): DreamUPAdminErrorState {
  if (!isApiError(error)) {
    return { kind: "unavailable", message: "DreamUP 管理服务暂时不可用，请稍后重试。" };
  }
  if (error.code === "admin_stepup.required") {
    return { kind: "step_up_required", message: "请先完成管理员二次验证。" };
  }
  switch (error.kind) {
    case "unauthorized":
      return { kind: "unauthenticated", message: "登录状态已失效，请重新登录。" };
    case "forbidden":
      return { kind: "forbidden", message: "你没有该 DreamUP 活动的管理权限。" };
    case "not_found":
      return { kind: "not_found", message: "活动或报名记录不存在，或你无权查看。" };
    case "conflict":
      return { kind: "conflict", message: "记录已被其他管理员更新，请刷新后重试。" };
    default:
      return { kind: "unavailable", message: "DreamUP 管理服务暂时不可用，请稍后重试。" };
  }
}
