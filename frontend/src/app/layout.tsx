//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Root application layout (providers, fonts, metadata)
//

import type { Metadata } from "next";
import type { PropsWithChildren } from "react";
import Script from "next/script";
import "@douyinfe/semi-ui/lib/es/_base/base.css";
import { SemiDesignProvider } from "@/components/providers/semi-design-provider";
import { RiskStepUpProvider } from "@/features/auth/components/risk-step-up-provider";
import { SYSTEM_NAME } from "@/lib/branding";
import { THEME_INITIALIZATION_SCRIPT } from "@/lib/theme/theme";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: SYSTEM_NAME,
    template: `%s | ${SYSTEM_NAME}`,
  },
  description: `${SYSTEM_NAME}提供统一、安全、清晰的身份与访问管理能力。`,
};

export default function RootLayout({ children }: PropsWithChildren) {
  return (
    <html lang="zh-CN" data-theme="light" suppressHydrationWarning>
      <body theme-mode="light" suppressHydrationWarning>
        <SemiDesignProvider>
          <RiskStepUpProvider>{children}</RiskStepUpProvider>
        </SemiDesignProvider>
        {/* Static script: no user-controlled interpolation. Runs before hydration to prevent a theme flash. */}
        <Script id="united-pass-theme" strategy="beforeInteractive">
          {THEME_INITIALIZATION_SCRIPT}
        </Script>
      </body>
    </html>
  );
}
