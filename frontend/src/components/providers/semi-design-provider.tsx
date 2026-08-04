"use client";

import type { ReactNode } from "react";
import "@douyinfe/semi-ui/react19-adapter";

type SemiDesignProviderProps = {
  children: ReactNode;
};

export function SemiDesignProvider({ children }: SemiDesignProviderProps) {
  return children;
}
