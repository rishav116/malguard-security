"use client";

import React, { useEffect, useRef } from "react";

interface Particle {
  x: number;
  y: number;
  size: number;
  speedX: number;
  speedY: number;
  color: string;
  alpha: number;
  targetAlpha: number;
}

export default function ParticleField({ count = 22 }: { count?: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener("resize", handleResize);

    const colors = [
      "rgba(34, 211, 238, ", // Cyan
      "rgba(139, 92, 246, ", // Purple
      "rgba(56, 189, 248, ", // Sky
      "rgba(167, 139, 250, ", // Soft purple
    ];

    const particles: Particle[] = [];

    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        size: Math.random() * 1.6 + 0.8,
        speedX: (Math.random() - 0.5) * 0.3,
        speedY: (Math.random() - 0.5) * 0.3,
        color: colors[Math.floor(Math.random() * colors.length)],
        alpha: Math.random() * 0.4 + 0.2,
        targetAlpha: Math.random() * 0.6 + 0.2,
      });
    }

    let mouseX = -1000;
    let mouseY = -1000;
    let mouseActive = false;
    let mouseTimeout: ReturnType<typeof setTimeout>;

    const handleMouseMove = (e: MouseEvent) => {
      mouseX = e.clientX;
      mouseY = e.clientY;
      mouseActive = true;
      clearTimeout(mouseTimeout);
      mouseTimeout = setTimeout(() => {
        mouseActive = false;
      }, 1500);
    };

    window.addEventListener("mousemove", handleMouseMove, { passive: true });

    // Pause rendering during scroll to give 100% GPU priority to page scrolling
    let isScrolling = false;
    let scrollTimeout: ReturnType<typeof setTimeout>;
    const handleScroll = () => {
      isScrolling = true;
      clearTimeout(scrollTimeout);
      scrollTimeout = setTimeout(() => {
        isScrolling = false;
      }, 80);
    };
    window.addEventListener("scroll", handleScroll, { passive: true });

    let isDocumentVisible = !document.hidden;
    const handleVisibilityChange = () => {
      isDocumentVisible = !document.hidden;
      if (isDocumentVisible) {
        animationFrameId = requestAnimationFrame(render);
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);

    const render = () => {
      if (!isDocumentVisible) return;

      // Yield frame immediately if user is actively scrolling
      if (isScrolling) {
        animationFrameId = requestAnimationFrame(render);
        return;
      }

      ctx.clearRect(0, 0, width, height);

      const numParticles = particles.length;

      // Single batched draw call for all connection lines
      ctx.beginPath();
      ctx.strokeStyle = "rgba(34, 211, 238, 0.08)";
      ctx.lineWidth = 0.5;

      for (let i = 0; i < numParticles; i++) {
        const p1 = particles[i];
        for (let j = i + 1; j < numParticles; j++) {
          const p2 = particles[j];
          const dx = p1.x - p2.x;
          if (Math.abs(dx) > 85) continue;
          const dy = p1.y - p2.y;
          if (Math.abs(dy) > 85) continue;

          if (dx * dx + dy * dy < 7225) {
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
          }
        }
      }
      ctx.stroke();

      // Draw and update each particle
      for (let i = 0; i < numParticles; i++) {
        const p = particles[i];
        p.x += p.speedX;
        p.y += p.speedY;

        // Subtle alpha breathing
        if (Math.abs(p.alpha - p.targetAlpha) < 0.015) {
          p.targetAlpha = Math.random() * 0.5 + 0.15;
        } else {
          p.alpha += (p.targetAlpha - p.alpha) * 0.015;
        }

        // Mouse reaction (only when mouse is actively moving)
        if (mouseActive) {
          const mdx = p.x - mouseX;
          const mdy = p.y - mouseY;
          if (Math.abs(mdx) < 90 && Math.abs(mdy) < 90) {
            const mDistSq = mdx * mdx + mdy * mdy;
            if (mDistSq < 8100 && mDistSq > 0) {
              const mDist = Math.sqrt(mDistSq);
              const force = (90 - mDist) / 90;
              p.x += (mdx / mDist) * force * 1.1;
              p.y += (mdy / mDist) * force * 1.1;
            }
          }
        }

        // Screen wrap
        if (p.x < 0) p.x = width;
        if (p.x > width) p.x = 0;
        if (p.y < 0) p.y = height;
        if (p.y > height) p.y = 0;

        // Draw particle
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `${p.color}${p.alpha})`;
        ctx.fill();
      }

      animationFrameId = requestAnimationFrame(render);
    };

    animationFrameId = requestAnimationFrame(render);

    return () => {
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("scroll", handleScroll);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      clearTimeout(mouseTimeout);
      clearTimeout(scrollTimeout);
      cancelAnimationFrame(animationFrameId);
    };
  }, [count]);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none w-screen h-screen z-0 opacity-50 transform-gpu will-change-transform"
    />
  );
}
