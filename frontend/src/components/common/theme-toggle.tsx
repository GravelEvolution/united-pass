"use client";

import { Button } from "@douyinfe/semi-ui";
import { IconMoon, IconSun } from "@douyinfe/semi-icons";
import { applyColorTheme } from "@/lib/theme/theme";
import styles from "./theme-toggle.module.css";

type ThemeToggleProps = {
  className?: string;
};

export function ThemeToggle({ className }: ThemeToggleProps) {
  function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    applyColorTheme(currentTheme === "dark" ? "light" : "dark");
  }

  return (
    <Button
      className={`${styles.toggle} ${className ?? ""}`}
      theme="light"
      type="tertiary"
      aria-label="切换亮色或暗色模式"
      title="切换亮色或暗色模式"
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
