import styles from "./status-badge.module.css";

type StatusTone = "success" | "warning" | "danger" | "neutral" | "info";

type StatusBadgeProps = {
  label: string;
  tone?: StatusTone;
};

export function StatusBadge({ label, tone = "neutral" }: StatusBadgeProps) {
  return <span className={`${styles.badge} ${styles[tone]}`}>{label}</span>;
}
