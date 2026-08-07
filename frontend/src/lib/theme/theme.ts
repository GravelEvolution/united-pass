//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Semi Design theme definitions (light and dark)
//

export type ColorTheme = "light" | "dark";

export const THEME_STORAGE_KEY = "united-pass-color-theme";
export const THEME_CHANGE_EVENT = "united-pass-theme-change";

export const THEME_INITIALIZATION_SCRIPT = `
(function () {
  var resolvedTheme = "light";
  try {
    var storedTheme = localStorage.getItem("${THEME_STORAGE_KEY}");
    resolvedTheme = storedTheme === "light" || storedTheme === "dark"
      ? storedTheme
      : window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  } catch (error) {
    resolvedTheme = "light";
  }

  document.documentElement.setAttribute("data-theme", resolvedTheme);

  function synchronizeSemiTheme() {
    if (!document.body) return false;
    document.body.setAttribute("theme-mode", resolvedTheme);
    return true;
  }

  if (!synchronizeSemiTheme()) {
    var bodyObserver = new MutationObserver(function () {
      if (synchronizeSemiTheme()) bodyObserver.disconnect();
    });
    bodyObserver.observe(document.documentElement, { childList: true });
  }
})();`;

export function applyColorTheme(theme: ColorTheme): void {
  document.documentElement.setAttribute("data-theme", theme);
  document.body.setAttribute("theme-mode", theme);
  localStorage.setItem(THEME_STORAGE_KEY, theme);
  window.dispatchEvent(new Event(THEME_CHANGE_EVENT));
}

export function getAppliedColorTheme(): ColorTheme {
  return document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
}

export function subscribeToColorTheme(onStoreChange: () => void): () => void {
  window.addEventListener(THEME_CHANGE_EVENT, onStoreChange);
  return () => window.removeEventListener(THEME_CHANGE_EVENT, onStoreChange);
}
