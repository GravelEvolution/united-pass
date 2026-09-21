//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Dashboard layout shell (sidebar and top bar)
//

"use client";

import type { ReactNode } from "react";
import { useEffect, useId, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Button } from "@douyinfe/semi-ui";
import {
  IconApps,
  IconClose,
  IconExit,
  IconHistory,
  IconHome,
  IconGlobe,
  IconKey,
  IconMenu,
  IconShield,
  IconUser,
  IconUserGroup,
} from "@douyinfe/semi-icons";
import { BrandMark } from "@/components/common/brand-mark";
import { ThemeToggle } from "@/components/common/theme-toggle";
import { UserAvatar } from "@/components/common/user-avatar";
import { getControlledAvatarUrl } from "@/lib/utils/avatar-url";
import type { CurrentUser } from "@/types/identity";
import type { PermissionCapabilities } from "@/types/permissions";
import { FULL_PERMISSIONS } from "@/types/permissions";
import styles from "./dashboard-shell.module.css";

type ShellMode = "account" | "admin";

type DashboardShellProps = {
  mode: ShellMode;
  currentUser: CurrentUser;
  /** Permission capabilities for filtering admin navigation. Account mode ignores this. */
  permissions?: PermissionCapabilities;
  showDreamUPAdministration?: boolean;
  children: ReactNode;
};

type NavigationItem = {
  href: string;
  label: string;
  icon: typeof IconHome;
  /** Required permission to show this item; undefined means always visible. */
  requiresPermission?: keyof PermissionCapabilities;
  requiresDreamUPAccess?: boolean;
};

const accountNavigation = [
  { href: "/account", label: "账户概览", icon: IconHome },
  { href: "/account/security", label: "登录与安全", icon: IconShield },
  { href: "/account/sessions", label: "活跃会话", icon: IconKey },
  { href: "/account/applications", label: "授权应用", icon: IconApps },
  { href: "/account/data-export", label: "数据导出", icon: IconHistory },
  { href: "/account/delete", label: "注销账户", icon: IconUser },
] satisfies NavigationItem[];

const adminNavigation = [
  { href: "/admin", label: "工作台", icon: IconHome },
  { href: "/admin/dreamup", label: "DreamUP 上海站", icon: IconApps, requiresDreamUPAccess: true },
  { href: "/admin/users", label: "用户", icon: IconUser, requiresPermission: "userRead" as const },
  { href: "/admin/employees", label: "员工", icon: IconUserGroup, requiresPermission: "userRead" as const },
  { href: "/admin/departments", label: "部门", icon: IconUserGroup, requiresPermission: "userRead" as const },
  { href: "/admin/providers", label: "Provider", icon: IconGlobe, requiresPermission: "providerRead" as const },
  { href: "/admin/applications", label: "OAuth 应用", icon: IconApps, requiresPermission: "applicationRead" as const },
  { href: "/admin/policies", label: "授权策略", icon: IconShield, requiresPermission: "policyRead" as const },
  { href: "/admin/audit", label: "审计事件", icon: IconHistory, requiresPermission: "auditRead" as const },
] satisfies NavigationItem[];

function isNavigationActive(pathname: string, href: string): boolean {
  return href === "/account" || href === "/admin"
    ? pathname === href
    : pathname.startsWith(href);
}

function filterByPermissions(
  items: NavigationItem[],
  permissions: PermissionCapabilities,
  showDreamUPAdministration: boolean,
): NavigationItem[] {
  return items.filter(
    (item) => (!item.requiresPermission || permissions[item.requiresPermission])
      && (!item.requiresDreamUPAccess || showDreamUPAdministration),
  );
}

export function DashboardShell({ mode, currentUser, permissions, showDreamUPAdministration = false, children }: DashboardShellProps) {
  const pathname = usePathname();
  const [menuOpenPath, setMenuOpenPath] = useState<string | null>(null);
  const navigationId = useId();
  const menuButtonId = `${navigationId}-button`;
  const isMenuOpen = menuOpenPath === pathname;
  const effectivePermissions = permissions ?? FULL_PERMISSIONS;
  const navigation = mode === "account"
    ? accountNavigation
    : filterByPermissions(adminNavigation, effectivePermissions, showDreamUPAdministration);
  const alternateHref = mode === "account" ? "/admin" : "/account";
  const alternateLabel = mode === "account" ? "进入管理后台" : "查看普通用户示例";
  const canShowAlternateSurface = mode === "admin" || Boolean(currentUser.employeeProfile);
  const profileDescription = mode === "admin"
    ? currentUser.email
    : currentUser.employeeProfile
      ? "外部用户 · 员工"
      : "普通外部用户";
  const profileAvatarUrl = getControlledAvatarUrl(currentUser.avatarUrl);

  useEffect(() => {
    if (!isMenuOpen) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setMenuOpenPath(null);
      document.getElementById(menuButtonId)?.focus();
    };
    document.addEventListener("keydown", closeOnEscape);

    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [isMenuOpen, menuButtonId]);

  return (
    <div className={styles.shell}>
      <header className={styles.mobileHeader}>
        <div className={styles.mobileBrand}>
          <BrandMark compact />
          <span>{mode === "account" ? "统一账户" : "管理控制台"}</span>
        </div>
        <div className={styles.mobileActions}>
          <ThemeToggle />
          <Button
            id={menuButtonId}
            aria-label={isMenuOpen ? "关闭导航" : "打开导航"}
            aria-expanded={isMenuOpen}
            aria-controls={navigationId}
            theme="borderless"
            icon={isMenuOpen ? <IconClose /> : <IconMenu />}
            onClick={() => setMenuOpenPath((openPath) => openPath === pathname ? null : pathname)}
          />
        </div>
      </header>

      {isMenuOpen && <button className={styles.backdrop} aria-label="关闭导航" onClick={() => setMenuOpenPath(null)} />}

      <aside id={navigationId} className={`${styles.sidebar} ${isMenuOpen ? styles.sidebarOpen : ""}`}>
        <Link className={styles.brandLink} href={mode === "account" ? "/account" : "/admin"}>
          <BrandMark />
        </Link>
        <Button
          className={styles.sidebarClose}
          aria-label="关闭导航"
          theme="borderless"
          icon={<IconClose />}
          onClick={() => {
            setMenuOpenPath(null);
            document.getElementById(menuButtonId)?.focus();
          }}
        />
        <div className={styles.surfaceRow}>
          <div className={styles.surfaceLabel}>{mode === "account" ? "账户中心" : "管理控制台"}</div>
          <ThemeToggle />
        </div>
        <nav className={styles.navigation} aria-label={mode === "account" ? "账户中心导航" : "管理后台导航"}>
          {navigation.map((navigationItem) => {
            const Icon = navigationItem.icon;
            const active = isNavigationActive(pathname, navigationItem.href);
            return (
              <Link
                key={navigationItem.href}
                href={navigationItem.href}
                className={`${styles.navigationItem} ${active ? styles.navigationItemActive : ""}`}
                aria-current={active ? "page" : undefined}
              >
                <Icon size="default" />
                {navigationItem.label}
              </Link>
            );
          })}
        </nav>
        <div className={styles.sidebarFooter}>
          {canShowAlternateSurface && (
            <Link className={styles.alternateLink} href={alternateHref}>{alternateLabel}</Link>
          )}
          <Link className={styles.logoutLink} href="/logout" onClick={() => setMenuOpenPath(null)}>
            <IconExit size="default" />
            <span>退出登录</span>
          </Link>
          <div className={styles.profile}>
            <UserAvatar className={styles.profileAvatar} displayName={currentUser.displayName} imageUrl={profileAvatarUrl} />
            <div>
              <strong>{currentUser.displayName}</strong>
              <span>{profileDescription}</span>
            </div>
          </div>
        </div>
      </aside>

      <main className={styles.main}>{children}</main>
    </div>
  );
}
