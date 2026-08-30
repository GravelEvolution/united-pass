import Link from "next/link";
import type { DreamUPAdminErrorState } from "../error-state";
import { DreamUPAdminStepUp } from "./dreamup-admin-step-up";
import styles from "./dreamup-admin.module.css";

export function DreamUPRouteState({ state, eventId }: { state: DreamUPAdminErrorState; eventId?: string }) {
  if (state.kind === "step_up_required" && eventId) {
    return <DreamUPAdminStepUp eventId={eventId} />;
  }
  const title = state.kind === "forbidden"
    ? "没有活动管理权限"
    : state.kind === "not_found"
      ? "没有找到记录"
      : state.kind === "unauthenticated"
        ? "需要重新登录"
        : state.kind === "conflict"
          ? "记录已发生变化"
          : state.kind === "step_up_required"
            ? "需要管理员二次验证"
            : "管理服务暂时不可用";
  const href = state.kind === "unauthenticated" ? "/login" : "/admin/dreamup";
  return (
    <section className={styles.routeState} role="alert">
      <span>MoonStone DreamUP 上海站</span>
      <h1>{title}</h1>
      <p>{state.message}</p>
      <Link href={href}>{state.kind === "unauthenticated" ? "重新登录" : "返回活动看板"}</Link>
    </section>
  );
}
