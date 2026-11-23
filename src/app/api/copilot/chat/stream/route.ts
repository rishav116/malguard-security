import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/**
 * Next.js API Proxy Route for Malix AI Assistant Real-Time SSE Stream
 * Securely forwards Authorization Bearer header to the FastAPI backend and pipes the SSE stream.
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

  const targetUrl = `${backendBase.replace(/\/+$/, "")}/api/v1/copilot/chat/stream`;

  try {
    const body = await req.json();
    const res = await fetch(targetUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "text/event-stream",
        Authorization: authHeader,
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const errText = await res.text();
      return new Response(errText, { status: res.status });
    }

    return new Response(res.body, {
      status: res.status,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
        "X-Accel-Buffering": "no",
      },
    });
  } catch (err) {
    return NextResponse.json(
      { detail: `Failed to proxy chat stream to FastAPI: ${(err as Error).message}` },
      { status: 502 }
    );
  }
}
