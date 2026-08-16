//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Notice for invalid or expired links
//

"use client";

import Link from "next/link";
import { Button } from "@douyinfe/semi-ui";
import { IconAlertTriangle } from "@douyinfe/semi-icons";
import styles from "./credential-panel.module.css";

type InvalidLinkNoticeProps = {
  title: string;
  description: string;
  actionHref: string;
  actionLabel: string;
};

export function InvalidLinkNotice({
  title,
  description,
  actionHref,
  actionLabel,
}: InvalidLinkNoticeProps) {
  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className={styles.statusCard} role="alert">
        <IconAlertTriangle size="extra-large" style={{ color: "var(--up-danger)" }} />
        <p>链接缺少必要的令牌参数，无法继续。请使用完整链接，或重新发起请求。</p>
      </div>
      <div className={styles.actions}>
        <Link href={actionHref}>
          <Button theme="solid" type="primary" size="large" block>{actionLabel}</Button>
        </Link>
      </div>
    </div>
  );
}
