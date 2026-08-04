import styles from "./brand-mark.module.css";

type BrandMarkProps = {
  compact?: boolean;
};

export function BrandMark({ compact = false }: BrandMarkProps) {
  return (
    <span className={styles.brand} aria-label="United Pass">
      <span className={styles.symbol} aria-hidden="true">
        <span />
        <span />
      </span>
      {!compact && <span className={styles.wordmark}>United Pass</span>}
    </span>
  );
}
