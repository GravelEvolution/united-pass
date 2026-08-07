//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Brand mark (logo) component
//

import Image from "next/image";
import { SYSTEM_NAME } from "@/lib/branding";
import styles from "./brand-mark.module.css";

type BrandMarkProps = {
  compact?: boolean;
  inverse?: boolean;
};

export function BrandMark({ compact = false, inverse = false }: BrandMarkProps) {
  return (
    <span className={`${styles.brand} ${inverse ? styles.inverse : ""}`} aria-label={SYSTEM_NAME}>
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
