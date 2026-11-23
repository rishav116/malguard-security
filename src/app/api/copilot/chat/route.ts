import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/**
 * Next.js API Proxy Route for Malix AI Assistant Chat (Non-streaming)
 * Securely forwards Authorization Bearer header to the FastAPI backend.
 */
export async function POST(req: NextRequest) {
  const authHeader = req.headers.get("authorization") || req.headers.get("Authorization");
  if (!authHeader || !authHeader.toLowerCase().startsWith("bearer ")) {
    return NextResponse.json(
      { detail: "Missing Authorization header with Bearer token." },
      { status: 401 }
    );
  }

  const backendBase =
    process.env.FASTAPI_INTERNAL_URL ||
    process.env.NEXT_PUBLIC_FASTAPI_URL ||
    "http://127.0.0.1:8000";

  const targetUrl = `${backendBase.replace(/\/+$/, "")}/api/v1/copilot/chat`;

  try {
    const body = await req.json();
    const res = await fetch(targetUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: authHeader,
      },
      body: JSON.stringify(body),
    });

    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      { detail: `Failed to proxy chat request to FastAPI: ${(err as Error).message}` },
      { status: 502 }
    );
  }
}
