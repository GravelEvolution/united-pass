import type { ReactNode } from "react";
import Link from "next/link";
import { BrandMark } from "@/components/common/brand-mark";
import { ThemeToggle } from "@/components/common/theme-toggle";
import { SYSTEM_NAME } from "@/lib/branding";
import styles from "./auth-shell.module.css";

type AuthShellProps = {
  children: ReactNode;
};

export function AuthShell({ children }: AuthShellProps) {
  return (
    <main className={styles.page}>
      <section className={styles.brandPanel} aria-label={`${SYSTEM_NAME}产品介绍`}>
        <Link href="/login"><BrandMark /></Link>
        <div className={styles.brandCopy}>
          <p className={styles.kicker}>IDENTITY, SIMPLIFIED</p>
          <h1>一个身份，连接每一次可信访问。</h1>
          <p>统一管理你的账户、员工身份、应用授权与安全会话。</p>
        </div>
        <div className={styles.securityNote}>
          <span className={styles.securityDot} />
          OAuth 2.0 与 OpenID Connect
        </div>
      </section>
      <section className={styles.contentPanel}>
        <ThemeToggle className={styles.themeToggle} />
        <div className={styles.mobileBrand}><BrandMark /></div>
        <div className={styles.content}>{children}</div>
        <footer className={styles.footer}>
          <span>© 2026 {SYSTEM_NAME}</span>
          <span aria-hidden="true">·</span>
          <Link href="/privacy">隐私政策</Link>
          <span aria-hidden="true">·</span>
          <Link href="/terms">服务条款</Link>
        </footer>
      </section>
    </main>
  );
}
