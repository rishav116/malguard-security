import { supabase } from "@/lib/supabase/client";

/**
 * MALGUARD AI — Gemini Copilot Service
 * Interfaces with the FastAPI Gemini AI Assistant backend.
 * Supports non-blocking asynchronous requests and real-time SSE streaming.
 */

export interface AuthTokenResult {
  token: string | null;
  error?: string;
  needsLogin?: boolean;
}

/**
 * Resolves a valid Supabase access token for API requests.
 * 1. If a valid, non-expired token is provided, uses it.
 * 2. Otherwise fetches the current session from supabase.auth.getSession().
 * 3. If the session is expiring or expired, automatically refreshes it via supabase.auth.refreshSession().
 * 4. Never returns a fabricated token.
 */
export async function getValidAuthToken(explicitToken?: string): Promise<AuthTokenResult> {
  // If an explicit token was passed, check if it's usable
  if (explicitToken && explicitToken.trim()) {
    try {
      const parts = explicitToken.trim().split(".");
      if (parts.length === 3) {
        const payload = JSON.parse(atob(parts[1]));
        const nowSec = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp > nowSec + 15) {
          return { token: explicitToken.trim() };
        }
      } else {
        // Non-JWT token format
        return { token: explicitToken.trim() };
      }
    } catch {
      // If parsing fails, fall through to getSession()
    }
  }

  // Obtain current authenticated session using the existing Supabase client
  try {
    const { data: { session }, error: sessionError } = await supabase.auth.getSession();

    if (sessionError) {
      console.warn("[copilotService] Supabase getSession error:", sessionError);
    }

    if (session?.access_token) {
      const nowSec = Math.floor(Date.now() / 1000);
      const isExpiring = session.expires_at ? session.expires_at <= nowSec + 30 : false;

      if (!isExpiring) {
        return { token: session.access_token };
      }

      // Token is expired or expiring in <= 30 seconds; refresh the session
      try {
        const { data: refreshed, error: refreshError } = await supabase.auth.refreshSession();
        if (refreshed?.session?.access_token) {
          return { token: refreshed.session.access_token };
        }
        if (refreshError) {
          console.warn("[copilotService] Supabase session refresh failed:", refreshError);
        }
      } catch (refreshEx) {
        console.warn("[copilotService] Refresh exception:", refreshEx);
      }
    }

    // Direct session refresh attempt if getSession had no token or expired
    try {
      const { data: refreshedData } = await supabase.auth.refreshSession();
      if (refreshedData?.session?.access_token) {
        return { token: refreshedData.session.access_token };
      }
    } catch {
      // Fall through to authentication required
    }

    return {
      token: null,
      error: "Authentication required. Please sign in to your MALGUARD AI account to chat with Malix AI Assistant.",
      needsLogin: true,
    };
  } catch (err) {
    return {
      token: null,
      error: `Authentication check failed: ${(err as Error).message}. Please log in again.`,
      needsLogin: true,
    };
  }
}

function getCandidateBaseUrls(): string[] {
  const configured = process.env.NEXT_PUBLIC_FASTAPI_URL?.trim().replace(/\/+$/, "");
  const isLocalhost =
    typeof window !== "undefined" &&
    (window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1" ||
      window.location.hostname === "0.0.0.0");

  if (configured) {
    if (isLocalhost) {
      return Array.from(
        new Set([configured, "http://localhost:8000", "http://127.0.0.1:8000"])
      );
    }
    return [configured];
  }

  // When deployed in production without explicit NEXT_PUBLIC_FASTAPI_URL, route to same-origin Vercel service
  if (typeof window !== "undefined" && !isLocalhost && window.location.origin) {
    return [window.location.origin];
  }

  return ["http://localhost:8000", "http://127.0.0.1:8000"];
}

export interface ChatMessage {
  role: "user" | "model";
  content: string;
}

export interface CopilotChatResponse {
  reply: string;
  scan_context_used?: {
    scan_id: string;
    file_name: string;
    sha256: string;
    verdict: string;
  } | null;
  model_used: string;
  grounded_on_scan: boolean;
  timestamp: string;
}

export interface SuggestedQuestionItem {
  id: string;
  title: string;
  prompt: string;
}

export interface SuggestedQuestionsData {
  categories: {
    english: SuggestedQuestionItem[];
    hinglish: SuggestedQuestionItem[];
    hindi: SuggestedQuestionItem[];
  };
}

export interface StreamMetadata {
  model?: string;
  grounded_on_scan?: boolean;
  scan_context?: {
    scan_id?: string;
    file_name?: string;
    sha256?: string;
    verdict?: string;
  } | null;
}

export interface StreamCallbacks {
  onToken: (token: string) => void;
  onMetadata?: (meta: StreamMetadata) => void;
  onDone?: (modelUsed: string) => void;
  onError?: (error: string) => void;
}

/**
 * Fetches curated security questions in English, Hinglish, and Hindi.
 */
export async function fetchSuggestedQuestions(): Promise<{
  success: boolean;
  data?: SuggestedQuestionsData;
  error?: string;
}> {
  const baseUrls = getCandidateBaseUrls();
  let lastError = "Unable to connect to server";

  for (const baseUrl of baseUrls) {
    try {
      const res = await fetch(`${baseUrl}/api/v1/copilot/suggested-questions`, {
        method: "GET",
        headers: {
          Accept: "application/json",
        },
        cache: "no-store",
      });

      if (!res.ok) {
        lastError = `Server returned HTTP ${res.status}`;
        continue;
      }

      const data: SuggestedQuestionsData = await res.json();
      return { success: true, data };
    } catch (err) {
      lastError = (err as Error).message;
    }
  }

  return { success: false, error: lastError };
}

/**
 * Parses and processes an active SSE ReadableStream from the backend.
 */
async function readEventStream(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  callbacks: StreamCallbacks
): Promise<void> {
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const blocks = buffer.split("\n\n");
    buffer = blocks.pop() || "";

    for (const block of blocks) {
      const trimmed = block.trim();
      if (!trimmed) continue;

      for (const line of trimmed.split("\n")) {
        if (line.startsWith("data: ")) {
          const jsonStr = line.slice(6).trim();
          try {
            const data = JSON.parse(jsonStr);
            if (data.event === "token" && typeof data.text === "string") {
              callbacks.onToken(data.text);
            } else if (data.event === "metadata") {
              callbacks.onMetadata?.(data);
            } else if (data.event === "done") {
              callbacks.onDone?.(data.model_used || "gemini");
            } else if (data.event === "error") {
              callbacks.onError?.(data.detail || "Streaming error occurred");
            }
          } catch {
            // Ignore partial JSON parse glitch on fragmented SSE chunks
          }
        }
      }
    }
  }

  // Flush any leftover buffer
  if (buffer.trim()) {
    for (const line of buffer.trim().split("\n")) {
      if (line.startsWith("data: ")) {
        try {
          const data = JSON.parse(line.slice(6).trim());
          if (data.event === "token" && typeof data.text === "string") {
            callbacks.onToken(data.text);
          }
        } catch {
          // Ignore
        }
      }
    }
  }
}

/**
 * Dispatches a chat message to Gemini AI Security Copilot (Non-streaming).
 */
export async function sendCopilotMessage(
  message: string,
  options: {
    history?: ChatMessage[];
    scanId?: string;
    authToken?: string;
  } = {}
): Promise<{
  success: boolean;
  data?: CopilotChatResponse;
  error?: string;
  needsLogin?: boolean;
}> {
  // 1. Obtain authenticated session token
  const authResult = await getValidAuthToken(options.authToken);
  if (!authResult.token) {
    return {
      success: false,
      error: authResult.error || "Authentication required. Please sign in to your MALGUARD AI account.",
      needsLogin: true,
    };
  }

  const baseUrls = getCandidateBaseUrls();
  let currentToken = authResult.token;

  const bodyPayload = {
    message: message.trim(),
    scan_id: options.scanId || null,
    history: options.history || [],
  };

  let lastError = "Unable to reach detection backend";

  for (const baseUrl of baseUrls) {
    try {
      const endpoint = `${baseUrl}/api/v1/copilot/chat`;
      let res = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Bearer ${currentToken}`,
        },
        body: JSON.stringify(bodyPayload),
      });

      // Handle 401 Unauthorized by attempting a token refresh
      if (res.status === 401) {
        try {
          const { data: refreshData } = await supabase.auth.refreshSession();
          if (refreshData?.session?.access_token && refreshData.session.access_token !== currentToken) {
            currentToken = refreshData.session.access_token;
            res = await fetch(endpoint, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
                Authorization: `Bearer ${currentToken}`,
              },
              body: JSON.stringify(bodyPayload),
            });
          }
        } catch {
          // Fall through to 401 rejection
        }
      }

      if (!res.ok) {
        if (res.status === 401) {
          return {
            success: false,
            error: "Your session has expired. Please sign in again to continue.",
            needsLogin: true,
          };
        }

        const errDetail = await res.text();
        let parsedDetail = `HTTP ${res.status}`;
        try {
          const j = JSON.parse(errDetail);
          parsedDetail = j.detail || parsedDetail;
        } catch {
          parsedDetail = errDetail || parsedDetail;
        }
        return { success: false, error: parsedDetail };
      }

      const data: CopilotChatResponse = await res.json();
      return { success: true, data };
    } catch (err) {
      lastError = `Network connection failure: ${(err as Error).message}`;
    }
  }

  return { success: false, error: lastError };
}

/**
 * Dispatches a real-time streaming chat message to Gemini AI Copilot via SSE.
 * Receives tokens progressively and calls onToken immediately for sub-second UI responsiveness.
 * Authenticated via Supabase Bearer token.
 */
export async function streamCopilotMessage(
  message: string,
  callbacks: StreamCallbacks,
  options: {
    history?: ChatMessage[];
    scanId?: string;
    authToken?: string;
    signal?: AbortSignal;
  } = {}
): Promise<void> {
  // 1. Obtain authenticated session token
  const authResult = await getValidAuthToken(options.authToken);
  if (!authResult.token) {
    callbacks.onError?.(
      authResult.error || "Authentication required. Please sign in to your MALGUARD AI account to chat with Malix AI Assistant."
    );
    return;
  }

  const baseUrls = getCandidateBaseUrls();
  let currentToken = authResult.token;

  const bodyPayload = {
    message: message.trim(),
    scan_id: options.scanId || null,
    history: options.history || [],
  };

  let lastError: string | null = null;
  let connectionMade = false;

  for (const baseUrl of baseUrls) {
    const endpoint = `${baseUrl}/api/v1/copilot/chat/stream`;

    try {
      let res = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "text/event-stream",
          Authorization: `Bearer ${currentToken}`,
        },
        body: JSON.stringify(bodyPayload),
        signal: options.signal,
      });

      // Handle 401 Unauthorized with token refresh
      if (res.status === 401) {
        try {
          const { data: refreshData } = await supabase.auth.refreshSession();
          if (refreshData?.session?.access_token && refreshData.session.access_token !== currentToken) {
            currentToken = refreshData.session.access_token;
            res = await fetch(endpoint, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Accept: "text/event-stream",
                Authorization: `Bearer ${currentToken}`,
              },
              body: JSON.stringify(bodyPayload),
              signal: options.signal,
            });
          }
        } catch {
          // Fall through
        }
      }

      connectionMade = true;

      if (!res.ok) {
        if (res.status === 401) {
          callbacks.onError?.("Your session has expired. Please sign in again to continue using Malix AI Assistant.");
          return;
        }

        const errDetail = await res.text();
        let parsedDetail = `HTTP ${res.status}`;
        try {
          const j = JSON.parse(errDetail);
          parsedDetail = j.detail || parsedDetail;
        } catch {
          parsedDetail = errDetail || parsedDetail;
        }
        callbacks.onError?.(parsedDetail);
        return;
      }

      const reader = res.body?.getReader();
      if (!reader) {
        callbacks.onError?.("No readable response stream available from server.");
        return;
      }

      await readEventStream(reader, callbacks);
      callbacks.onDone?.("gemini");
      return;
    } catch (err: unknown) {
      if ((err as Error).name === "AbortError") {
        return;
      }
      lastError = `Connection failure: ${(err as Error).message}`;
      // If we got past fetch, don't try another endpoint
      if (connectionMade) {
        callbacks.onError?.(lastError);
        return;
      }
    }
  }

  callbacks.onError?.(
    lastError ||
      "Unable to contact Malix AI detection backend. Ensure the FastAPI backend server is online."
  );
}
