import Image from "next/image";
import { SYSTEM_NAME } from "@/lib/branding";
import styles from "./brand-mark.module.css";

type BrandMarkProps = {
  compact?: boolean;
};

export function BrandMark({ compact = false }: BrandMarkProps) {
  return (
    <span className={styles.brand} aria-label={SYSTEM_NAME}>
      <Image
        className={styles.logo}
        src="/brand/gravel-evolution-logo.png"
        width={44}
        height={44}
        alt=""
        aria-hidden="true"
      />
      {!compact && <span className={styles.wordmark}>{SYSTEM_NAME}</span>}
    </span>
  );
}
