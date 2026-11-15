"use client";

import React, { useEffect, useRef } from "react";
import { gsap } from "gsap";

export default function SmoothScroll({ children }: { children: React.ReactNode }) {
  const currentYRef = useRef(0);
  const targetYRef = useRef(0);
  const isRunningRef = useRef(false);

  useEffect(() => {
    if (typeof window === "undefined") return;

    // Keep 100% native gesture scrolling on mobile phones and tablets
    const isMobile =
      ("ontouchstart" in window || navigator.maxTouchPoints > 0) &&
      window.matchMedia("(max-width: 768px)").matches;

    const prefersReducedMotion =
      window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (isMobile || prefersReducedMotion) {
      return;
    }

    currentYRef.current = window.scrollY;
    targetYRef.current = window.scrollY;

    const getMaxScroll = () => {
      return Math.max(
        0,
        document.documentElement.scrollHeight - window.innerHeight
      );
    };

    // Fast-path scrollable container check
    const isInsideScrollable = (el: HTMLElement | null): boolean => {
      let current: HTMLElement | null = el;
      while (current && current !== document.body && current !== document.documentElement) {
        if (
          current.classList.contains("overflow-y-auto") ||
          current.classList.contains("overflow-y-scroll") ||
          current.getAttribute("role") === "dialog" ||
          current.dataset.scrollable !== undefined
        ) {
          if (current.scrollHeight > current.clientHeight) return true;
        }
        current = current.parentElement;
      }
      return false;
    };

    // High refresh rate ticker synced with 60Hz / 120Hz / 144Hz / 240Hz monitors
    const onTick = () => {
      if (!isRunningRef.current) return;

      const diff = targetYRef.current - currentYRef.current;

      // Sub-pixel settle check - zero micro-snap jitter
      if (Math.abs(diff) < 0.25) {
        currentYRef.current = targetYRef.current;
        window.scrollTo(0, Math.round(currentYRef.current));
        isRunningRef.current = false;
        return;
      }

      // Buttery fluid damping factor: 0.098 provides a silky smooth glide without jitter
      currentYRef.current += diff * 0.098;
      window.scrollTo(0, currentYRef.current);
    };

    gsap.ticker.add(onTick);
    gsap.ticker.lagSmoothing(500, 33);

    const handleWheel = (e: WheelEvent) => {
      if (isInsideScrollable(e.target as HTMLElement | null)) {
        return;
      }

      e.preventDefault();

      let delta = e.deltaY;
      // Normalize delta modes across all browsers & mice
      if (e.deltaMode === 1) delta *= 34; // lines
      else if (e.deltaMode === 2) delta *= window.innerHeight; // pages

      // Sync base when starting from idle
      if (!isRunningRef.current) {
        currentYRef.current = window.scrollY;
        targetYRef.current = window.scrollY;
        isRunningRef.current = true;
      }

      const maxScroll = getMaxScroll();
      // Continuous momentum accumulation - zero threshold jitter
      targetYRef.current = Math.max(0, Math.min(targetYRef.current + delta * 0.88, maxScroll));
    };

    const handleNativeScroll = () => {
      if (!isRunningRef.current) {
        currentYRef.current = window.scrollY;
        targetYRef.current = window.scrollY;
      }
    };

    // Smooth anchor navigation (#features, #workflow, etc.)
    const handleAnchorClick = (e: MouseEvent) => {
      const target = (e.target as HTMLElement)?.closest("a");
      if (!target) return;

      const href = target.getAttribute("href");
      if (href && href.startsWith("#") && href.length > 1) {
        const id = href.slice(1);
        const element = document.getElementById(id);
        if (element) {
          e.preventDefault();
          const targetOffset = Math.max(
            0,
            Math.min(
              window.scrollY + element.getBoundingClientRect().top - 72,
              getMaxScroll()
            )
          );
          currentYRef.current = window.scrollY;
          targetYRef.current = targetOffset;
          isRunningRef.current = true;
          window.history.pushState(null, "", href);
        }
      }
    };

    // Smooth keyboard navigation (ArrowUp, ArrowDown, PageDown, PageUp, Space, Home, End)
    const handleKeyDown = (e: KeyboardEvent) => {
      const activeTag = (document.activeElement?.tagName || "").toLowerCase();
      if (activeTag === "input" || activeTag === "textarea" || activeTag === "select") {
        return;
      }

      let delta = 0;
      if (e.key === "ArrowDown") delta = 100;
      else if (e.key === "ArrowUp") delta = -100;
      else if (e.key === "PageDown" || (e.key === " " && !e.shiftKey)) delta = window.innerHeight * 0.8;
      else if (e.key === "PageUp" || (e.key === " " && e.shiftKey)) delta = -window.innerHeight * 0.8;
      else if (e.key === "Home") {
        e.preventDefault();
        currentYRef.current = window.scrollY;
        targetYRef.current = 0;
        isRunningRef.current = true;
        return;
      } else if (e.key === "End") {
        e.preventDefault();
        currentYRef.current = window.scrollY;
        targetYRef.current = getMaxScroll();
        isRunningRef.current = true;
        return;
      }

      if (delta !== 0) {
        e.preventDefault();
        if (!isRunningRef.current) {
          currentYRef.current = window.scrollY;
          targetYRef.current = window.scrollY;
          isRunningRef.current = true;
        }
        targetYRef.current = Math.max(0, Math.min(targetYRef.current + delta, getMaxScroll()));
      }
    };

    window.addEventListener("wheel", handleWheel, { passive: false });
    window.addEventListener("scroll", handleNativeScroll, { passive: true });
    window.addEventListener("keydown", handleKeyDown);
    document.addEventListener("click", handleAnchorClick);

    return () => {
      window.removeEventListener("wheel", handleWheel);
      window.removeEventListener("scroll", handleNativeScroll);
      window.removeEventListener("keydown", handleKeyDown);
      document.removeEventListener("click", handleAnchorClick);
      gsap.ticker.remove(onTick);
    };
  }, []);

  return <>{children}</>;
}
