//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Global loading fallback
//

import styles from "./route-state.module.css";

export default function Loading() {
  return <div className={styles.state} role="status" aria-label="页面加载中"><div className={styles.loader} /></div>;
}
