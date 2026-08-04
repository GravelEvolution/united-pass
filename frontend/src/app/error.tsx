"use client";

import { Button } from "@douyinfe/semi-ui";
import { SYSTEM_NAME } from "@/lib/branding";
import styles from "./route-state.module.css";

export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className={styles.state}>
      <section className={styles.card}>
        <div className={styles.mark} aria-hidden="true">!</div>
        <h1>页面暂时无法加载</h1>
        <p>可能是临时问题。请重试；如果问题持续存在，请联系{SYSTEM_NAME}支持人员。</p>
        <Button type="primary" theme="solid" onClick={reset}>重新加载</Button>
      </section>
    </main>
  );
}
