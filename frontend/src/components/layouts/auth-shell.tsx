//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Authentication pages layout shell
//

import type { ReactNode } from "react";
import Link from "next/link";
import { BrandMark } from "@/components/common/brand-mark";
import { ThemeToggle } from "@/components/common/theme-toggle";
import { AuthBrandCarousel } from "@/components/layouts/auth-brand-carousel";
import { COMPANY_LEGAL_NAME, SYSTEM_NAME } from "@/lib/branding";
import styles from "./auth-shell.module.css";

type AuthShellProps = {
  children: ReactNode;
};

export function AuthShell({ children }: AuthShellProps) {
  return (
    <main className={styles.page}>
      <section className={styles.brandPanel} aria-label={`${SYSTEM_NAME}产品介绍`}>
        <AuthBrandCarousel />
        <Link className={styles.brandLogoLink} href="/login">
          <BrandMark inverse />
        </Link>
        <div className={styles.brandCopy}>
          <p className={styles.kicker}>HIGH-TECH ENTERPRISE, YOUTH-DEVELOP</p>
          <h1>我们始终相信老登和小登一起能迸发出最强的力量</h1>
          <p>We’ve always believed that the combination of the experienced and the young can burst forth with the strongest energy together.</p>
        </div>
      </section>
      <section className={styles.contentPanel}>
        <ThemeToggle className={styles.themeToggle} />
        <div className={styles.mobileBrand}><BrandMark /></div>
        <div className={styles.content}>{children}</div>
        <footer className={styles.footer}>
          <span>© 2026 {COMPANY_LEGAL_NAME}</span>
          <span aria-hidden="true">·</span>
          <Link href="/privacy">隐私政策</Link>
          <span aria-hidden="true">·</span>
          <Link href="/terms">服务条款</Link>
        </footer>
      </section>
    </main>
  );
}
