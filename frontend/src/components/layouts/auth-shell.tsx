import type { ReactNode } from "react";
import Link from "next/link";
import { BrandMark } from "@/components/common/brand-mark";
import styles from "./auth-shell.module.css";

type AuthShellProps = {
  children: ReactNode;
};

export function AuthShell({ children }: AuthShellProps) {
  return (
    <main className={styles.page}>
      <section className={styles.brandPanel} aria-label="United Pass 产品介绍">
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
        <div className={styles.mobileBrand}><BrandMark /></div>
        <div className={styles.content}>{children}</div>
        <p className={styles.footer}>© 2026 United Pass · 隐私 · 服务条款</p>
      </section>
    </main>
  );
}
