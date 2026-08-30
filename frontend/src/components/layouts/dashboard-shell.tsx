//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Dashboard layout shell (sidebar and top bar)
//

"use client";

import type { ReactNode } from "react";
import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Avatar, Button } from "@douyinfe/semi-ui";
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
import type { CurrentUser } from "@/types/identity";
import type { PermissionCapabilities } from "@/types/permissions";
import { canAccessAdminConsole, NO_PERMISSIONS } from "@/types/permissions";
import styles from "./dashboard-shell.module.css";

const DEFAULT_AVATAR_URL =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ccircle cx='50' cy='50' r='50' fill='%23eef1f6'/%3E%3Ccircle cx='50' cy='38' r='16' fill='%23b6bfcc'/%3E%3Cpath d='M50 58c-15 0-26 9-26 21v4h52v-4c0-12-11-21-26-21z' fill='%23b6bfcc'/%3E%3C/svg%3E";

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
  requiresAdminAccess?: boolean;
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
  { href: "/admin", label: "工作台", icon: IconHome, requiresAdminAccess: true },
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
      && (!item.requiresAdminAccess || canAccessAdminConsole(permissions))
      && (!item.requiresDreamUPAccess || showDreamUPAdministration),
  );
}

export function DashboardShell({ mode, currentUser, permissions, showDreamUPAdministration = false, children }: DashboardShellProps) {
  const pathname = usePathname();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const effectivePermissions = permissions ?? NO_PERMISSIONS;
  const navigation = mode === "account"
    ? accountNavigation
    : filterByPermissions(adminNavigation, effectivePermissions, showDreamUPAdministration);
  const alternateHref = mode === "account" ? "/admin" : "/account";
  const alternateLabel = mode === "account" ? "进入管理后台" : "返回账户中心";
  const canAccessAdmin = canAccessAdminConsole(effectivePermissions);
  const canShowAlternateSurface = mode === "admin" ? true : canAccessAdmin;
  const profileDescription = mode === "admin"
    ? currentUser.email
    : currentUser.employeeProfile
      ? "外部用户 · 员工"
      : "普通外部用户";

  return (
    <div className={styles.shell}>
      <header className={styles.mobileHeader}>
        <BrandMark />
        <div className={styles.mobileActions}>
          <ThemeToggle />
          <Button
            aria-label={isMenuOpen ? "关闭导航" : "打开导航"}
            theme="borderless"
            icon={isMenuOpen ? <IconClose /> : <IconMenu />}
            onClick={() => setIsMenuOpen((open) => !open)}
          />
        </div>
      </header>

      {isMenuOpen && <button className={styles.backdrop} aria-label="关闭导航" onClick={() => setIsMenuOpen(false)} />}

      <aside className={`${styles.sidebar} ${isMenuOpen ? styles.sidebarOpen : ""}`}>
        <Link
          className={styles.brandLink}
          href={mode === "account" ? "/account" : canAccessAdmin ? "/admin" : "/admin/dreamup"}
        >
          <BrandMark />
        </Link>
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
                onClick={() => setIsMenuOpen(false)}
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
          <div className={styles.profile}>
            <Avatar size="small" src={currentUser.avatarUrl ?? DEFAULT_AVATAR_URL} />
            <div>
              <strong>{currentUser.displayName}</strong>
              <span>{profileDescription}</span>
            </div>
          </div>
          <Link href="/logout" className={styles.logoutButton}>
            <IconExit size="default" />
            <span>退出登录</span>
          </Link>
        </div>
      </aside>

      <main className={styles.main}>{children}</main>
    </div>
  );
}
