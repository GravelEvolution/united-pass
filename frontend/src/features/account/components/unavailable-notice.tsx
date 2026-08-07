//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Notice for features unavailable in the frozen milestone
//

"use client";

import Link from "next/link";
import { Banner, Button } from "@douyinfe/semi-ui";
import styles from "./unavailable-notice.module.css";

type UnavailableNoticeProps = {
  bannerTitle: string;
  bannerDescription: string;
};

export function UnavailableNotice({ bannerTitle, bannerDescription }: UnavailableNoticeProps) {
  return (
    <div className={styles.container}>
      <Banner
        type="warning"
        fullMode={false}
        bordered
        closeIcon={null}
        title={bannerTitle}
        description={bannerDescription}
      />
      <Link href="/account" className={styles.backLink}>
        <Button theme="outline">返回账户中心</Button>
      </Link>
    </div>
  );
}
