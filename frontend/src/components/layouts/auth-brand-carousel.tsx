"use client";

import { useSyncExternalStore } from "react";
import Image from "next/image";
import styles from "./auth-shell.module.css";

const DESKTOP_MEDIA_QUERY = "(min-width: 901px)";

function subscribeToDesktopViewport(onStoreChange: () => void): () => void {
  const mediaQuery = window.matchMedia(DESKTOP_MEDIA_QUERY);
  mediaQuery.addEventListener("change", onStoreChange);
  return () => mediaQuery.removeEventListener("change", onStoreChange);
}

function getDesktopViewportSnapshot(): boolean {
  return window.matchMedia(DESKTOP_MEDIA_QUERY).matches;
}

function getServerDesktopViewportSnapshot(): boolean {
  return false;
}

export function AuthBrandCarousel() {
  const isDesktopViewport = useSyncExternalStore(
    subscribeToDesktopViewport,
    getDesktopViewportSnapshot,
    getServerDesktopViewportSnapshot,
  );

  if (!isDesktopViewport) return null;

  return (
    <div className={styles.brandCarousel} aria-hidden="true">
      <Image
        className={styles.brandSlide}
        src="/brand/auth-carousel-1.jpg"
        alt=""
        fill
        sizes="60vw"
        loading="eager"
        fetchPriority="high"
      />
      <Image
        className={styles.brandSlide}
        src="/brand/auth-carousel-2-v2.jpg"
        alt=""
        fill
        sizes="60vw"
      />
      <Image
        className={styles.brandSlide}
        src="/brand/auth-carousel-3.jpg"
        alt=""
        fill
        sizes="60vw"
      />
    </div>
  );
}
