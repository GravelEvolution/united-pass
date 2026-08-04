import Link from "next/link";
import styles from "./route-state.module.css";

export default function NotFound() {
  return (
    <main className={styles.state}>
      <section className={styles.card}>
        <div className={styles.mark} aria-hidden="true">404</div>
        <h1>找不到这个页面</h1>
        <p>页面可能已移动，或者你没有可用的访问入口。</p>
        <Link href="/account">返回账户中心</Link>
      </section>
    </main>
  );
}
