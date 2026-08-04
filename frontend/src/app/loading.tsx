import styles from "./route-state.module.css";

export default function Loading() {
  return <div className={styles.state} role="status" aria-label="页面加载中"><div className={styles.loader} /></div>;
}
