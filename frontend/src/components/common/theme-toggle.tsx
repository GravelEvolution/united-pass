//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Light and dark theme toggle component
//

"use client";

import { useSyncExternalStore } from "react";
import { Button } from "@douyinfe/semi-ui";
import { IconMoon, IconSun } from "@douyinfe/semi-icons";
import {
  applyColorTheme,
  getAppliedColorTheme,
  subscribeToColorTheme,
} from "@/lib/theme/theme";
import styles from "./theme-toggle.module.css";

type ThemeToggleProps = {
  className?: string;
};

export function ThemeToggle({ className }: ThemeToggleProps) {
  const theme = useSyncExternalStore(subscribeToColorTheme, getAppliedColorTheme, () => "light");
  const isDarkTheme = theme === "dark";
  const accessibleLabel = isDarkTheme ? "切换到亮色模式" : "切换到暗色模式";

  function toggleTheme() {
    applyColorTheme(isDarkTheme ? "light" : "dark");
  }

  return (
    <Button
      className={`${styles.toggle} ${className ?? ""}`}
      theme="light"
      type="tertiary"
      aria-label={accessibleLabel}
      aria-pressed={isDarkTheme}
      title={accessibleLabel}
      icon={
        <span className={styles.icons} aria-hidden="true">
          <IconMoon className={styles.moon} />
          <IconSun className={styles.sun} />
        </span>
      }
      onClick={toggleTheme}
    />
  );
}
