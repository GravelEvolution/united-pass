//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Semi Design UI provider (theme configuration)
//

"use client";

import type { ReactNode } from "react";
import "@douyinfe/semi-ui/react19-adapter";

type SemiDesignProviderProps = {
  children: ReactNode;
};

export function SemiDesignProvider({ children }: SemiDesignProviderProps) {
  return children;
}
