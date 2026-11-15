/**
 * MALGUARD AI — Gemini Copilot Service
 * Interfaces with the FastAPI Gemini AI Assistant backend.
 * Supports non-blocking asynchronous requests and real-time SSE streaming.
 */

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
}> {
  const baseUrls = getCandidateBaseUrls();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  if (options.authToken) {
    headers["Authorization"] = `Bearer ${options.authToken}`;
  }

  const bodyPayload = {
    message: message.trim(),
    scan_id: options.scanId || null,
    history: options.history || [],
  };

  let lastError = "Unable to reach detection backend";

  for (const baseUrl of baseUrls) {
    try {
      const endpoint = `${baseUrl}/api/v1/copilot/chat`;
      const res = await fetch(endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(bodyPayload),
      });

      if (!res.ok) {
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
  const baseUrls = getCandidateBaseUrls();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "text/event-stream",
  };

  if (options.authToken) {
    headers["Authorization"] = `Bearer ${options.authToken}`;
  }

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
      const res = await fetch(endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(bodyPayload),
        signal: options.signal,
      });

      connectionMade = true;

      if (!res.ok) {
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
