//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Placeholder action button for mocked frozen features
//

"use client";

import type { ReactNode } from "react";
import { Button, Toast } from "@douyinfe/semi-ui";

type MockActionButtonProps = {
  children: ReactNode;
  message: string;
  danger?: boolean;
  primary?: boolean;
  block?: boolean;
};

export function MockActionButton({ children, message, danger = false, primary = false, block = false }: MockActionButtonProps) {
  return (
    <Button
      block={block}
      type={danger ? "danger" : primary ? "primary" : "tertiary"}
      theme={primary ? "solid" : "outline"}
      onClick={() => Toast.info({ content: `${message}（当前仅为 Mock，不会变更数据）` })}
    >
      {children}
    </Button>
  );
}
