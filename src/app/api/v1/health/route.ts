import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/**
 * Next.js API Proxy Route for Detection Engine Health Check
 * Securely probes FastAPI backend server-side, avoiding browser Mixed Content and CORS restrictions.
 */
export async function GET(req: NextRequest) {
  const backendBase =
    process.env.FASTAPI_INTERNAL_URL ||
    process.env.NEXT_PUBLIC_FASTAPI_URL ||
    "http://127.0.0.1:8000";

  const cleanBase = backendBase.replace(/\/+$/, "");
  const targetUrls = [
    `${cleanBase}/api/v1/health`,
    `${cleanBase}/health`,
  ];

  for (const targetUrl of targetUrls) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4500);

      const res = await fetch(targetUrl, {
        method: "GET",
        headers: {
          Accept: "application/json",
        },
        signal: controller.signal,
        cache: "no-store",
      });

      clearTimeout(timeoutId);

      if (res.ok) {
        const data = await res.json();
        return NextResponse.json(data, {
          status: 200,
          headers: {
            "Cache-Control": "no-store, no-cache, must-revalidate",
          },
        });
      }
    } catch {
      continue;
    }
  }

  // Graceful structured response when backend is offline
  return NextResponse.json(
    {
      status: "offline",
      service: "MALGUARD AI",
      version: "1.0.0",
      environment: process.env.NODE_ENV || "development",
      engines: {
        pe_analyzer: "available (client-side Web Crypto & PE parser)",
        clamav_daemon: "offline (FastAPI backend is offline)",
        random_forest_ml: "offline (FastAPI backend is offline)",
      },
      message: "Detection Engine Not Connected (FastAPI backend is offline)",
    },
    { status: 503 }
  );
}
