"use client";

import React, { useRef } from "react";
import { motion, useInView, useReducedMotion, type Variants } from "framer-motion";

export interface FadeInSectionProps {
  children: React.ReactNode;
  direction?: "up" | "down" | "left" | "right" | "none";
  distance?: number;
  scale?: number;
  duration?: number;
  delay?: number;
  blur?: boolean;
  once?: boolean;
  margin?: string;
  immediate?: boolean;
  className?: string;
  as?: "div" | "section" | "article" | "span" | "header" | "footer" | "aside";
}

// Cubic bezier ease curve matching ArcadeCalc / Apple high-end pop-up
const POP_UP_EASE = [0.25, 0.1, 0.25, 1] as const;

export default function FadeInSection({
  children,
  direction = "up",
  distance = 32,
  scale = 0.97,
  duration = 0.6,
  delay = 0,
  blur = false,
  once = true,
  margin = "0px 0px -50px 0px",
  immediate = false,
  className = "",
  as = "div",
}: FadeInSectionProps) {
  const ref = useRef<HTMLDivElement>(null);
  const shouldReduceMotion = useReducedMotion();

  // Root margin threshold matching ArcadeCalc
  const isInView = useInView(ref, {
    once,
    margin: margin as any,
  });

  const isVisible = immediate || isInView || shouldReduceMotion;

  // Calculate translation vectors
  const getInitialPosition = () => {
    if (shouldReduceMotion) return { x: 0, y: 0 };
    switch (direction) {
      case "up":
        return { x: 0, y: distance };
      case "down":
        return { x: 0, y: -distance };
      case "left":
        return { x: distance, y: 0 };
      case "right":
        return { x: -distance, y: 0 };
      case "none":
      default:
        return { x: 0, y: 0 };
    }
  };

  const initialPos = getInitialPosition();

  const variants: Variants = {
    hidden: {
      opacity: 0,
      x: initialPos.x,
      y: initialPos.y,
      scale: shouldReduceMotion ? 1 : scale,
      filter: blur && !shouldReduceMotion ? "blur(8px)" : "none",
    },
    visible: {
      opacity: 1,
      x: 0,
      y: 0,
      scale: 1,
      filter: "blur(0px)",
      transition: {
        duration: shouldReduceMotion ? 0 : duration,
        delay: shouldReduceMotion ? 0 : delay,
        ease: POP_UP_EASE,
      },
    },
  };

  const MotionComponent = (motion as any)[as] || motion.div;

  return (
    <MotionComponent
      ref={ref}
      initial="hidden"
      animate={isVisible ? "visible" : "hidden"}
      variants={variants}
      className={className}
    >
      {children}
    </MotionComponent>
  );
}
