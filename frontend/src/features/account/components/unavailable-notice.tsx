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
