import { supabase } from "@/lib/supabase/client";

/**
 * MALGUARD AI — Detection Engine Service
 * Prepares client-to-backend communication for the future FastAPI ML/Signature engine.
 */

export interface DetectionEngineStatus {
  connected: boolean;
  endpoint: string;
  message: string;
  version?: string;
  supportedEngines?: string[];
  latencyMs?: number;
  lastChecked: string;
}

export interface FastAPIScanResponse {
  scan_id: string;
  file_name: string;
  file_size_bytes: number;
  formatted_size: string;
  hashes: {
    sha256: string;
    sha1: string;
    md5: string;
  };
  owner_id: string;
  timestamp: string;
  pe_analysis: {
    status: string;
    headers: {
      machine: string;
      subsystem: string;
      number_of_sections: number;
      compilation_timestamp?: string;
    };
    sections: Array<{
      name: string;
      virtual_size: number;
      raw_size: number;
      entropy: number;
    }>;
    imported_dlls_count: number;
    total_imports_count: number;
    file_entropy: number;
    suspicious_indicators: string[];
  };
  clamav: {
    status: string;
    available: boolean;
    matched: boolean;
    signature_name?: string | null;
    message: string;
  };
  ml_inference: {
    status: string;
    available: boolean;
    model_name: string;
    prediction?: string | null;
    confidence_score?: number | null;
    message: string;
  };
  verdict: "MALICIOUS" | "SUSPICIOUS" | "NO_THREAT_DETECTED" | "INCONCLUSIVE";
  verdict_reasons: string[];
  pipeline_status: string;
}

function getFastApiCandidates(): string[] {
  const configured = process.env.NEXT_PUBLIC_FASTAPI_URL?.trim().replace(/\/+$/, "");
  const isLocalhost =
    typeof window !== "undefined" &&
    (window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1" ||
      window.location.hostname === "0.0.0.0");

  if (configured) {
    if (isLocalhost) {
      return Array.from(
        new Set([configured, "http://127.0.0.1:8000", "http://localhost:8000"])
      );
    }
    return [configured];
  }

  // When deployed in production without explicit NEXT_PUBLIC_FASTAPI_URL, route to same-origin Vercel service
  if (typeof window !== "undefined" && !isLocalhost && window.location.origin) {
    return [window.location.origin];
  }

  return ["http://127.0.0.1:8000", "http://localhost:8000"];
}

const FASTAPI_BASE_URL =
  process.env.NEXT_PUBLIC_FASTAPI_URL?.trim().replace(/\/+$/, "") ||
  (typeof window !== "undefined" &&
  window.location.hostname !== "localhost" &&
  window.location.hostname !== "127.0.0.1"
    ? window.location.origin
    : "http://127.0.0.1:8000");

/**
 * Probes the FastAPI detection engine health endpoint.
 * Returns structured connection status without throwing uncaught exceptions.
 */
export async function checkDetectionEngineHealth(): Promise<DetectionEngineStatus> {
  const urls = getFastApiCandidates();
  const startTime = performance.now();
  const timestamp = new Date().toLocaleTimeString();

  for (const baseUrl of urls) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3500);

      const response = await fetch(`${baseUrl}/api/v1/health`, {
        method: "GET",
        headers: {
          Accept: "application/json",
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      const latencyMs = Math.round(performance.now() - startTime);

      if (response.ok) {
        const data = await response.json();
        return {
          connected: true,
          endpoint: baseUrl,
          message: "Detection Engine is online and ready for binary classification.",
          version: data.version || "1.0.0",
          supportedEngines: data.supported_engines || [
            "Random Forest PE Classifier",
            "ClamAV Signature Engine",
            "Gemini Security Reasoner",
          ],
          latencyMs,
          lastChecked: timestamp,
        };
      }
    } catch {
      continue;
    }
  }

  return {
    connected: false,
    endpoint: FASTAPI_BASE_URL,
    message: "Detection Engine Not Connected (FastAPI backend is offline)",
    lastChecked: timestamp,
  };
}

/**
 * Submits a validated Windows PE binary to the FastAPI backend for classification.
 * If backend is unreachable, gracefully returns a descriptive failure state.
 */
export async function submitBinaryForScan(
  file: File,
  metadata: {
    sha256: string;
    architecture: string;
    isDLL: boolean;
  },
  authToken?: string
): Promise<{ success: boolean; data?: FastAPIScanResponse; error?: string }> {
  // First verify backend availability
  const health = await checkDetectionEngineHealth();
  if (!health.connected) {
    return {
      success: false,
      error:
        "Detection Engine Not Connected. Actual machine learning classification and signature matching require an active FastAPI server at " +
        FASTAPI_BASE_URL +
        ".",
    };
  }

  const endpoint = `${health.endpoint}/api/v1/scan`;

  try {
    // For files > 4.0 MB (up to 10 MB), direct upload to private Supabase Storage bypasses Vercel's 4.5 MB Function payload limit (accounting for multipart boundary overhead)
    if (file.size > 4.0 * 1024 * 1024) {
      try {
        const storagePath = `${Date.now()}_${Math.random().toString(36).substring(2, 9)}_${file.name.replace(/[^a-zA-Z0-9._-]/g, "_")}`;
        const { data: uploadData, error: uploadError } = await supabase.storage
          .from("malguard-quarantine")
          .upload(storagePath, file, { upsert: false });

        if (!uploadError && uploadData) {
          const storageEndpoint = `${health.endpoint}/api/v1/scan/storage`;
          const storageResp = await fetch(storageEndpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Accept: "application/json",
              ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
            },
            body: JSON.stringify({
              storage_path: storagePath,
              file_name: file.name,
              sha256: metadata.sha256,
            }),
          });

          if (storageResp.ok) {
            const data: FastAPIScanResponse = await storageResp.json();
            return {
              success: true,
              data,
            };
          }
        }
      } catch (storageErr) {
        console.warn("Direct storage upload fallback to direct dispatch:", storageErr);
      }
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("sha256", metadata.sha256);
    formData.append("architecture", metadata.architecture);
    formData.append("is_dll", String(metadata.isDLL));

    const headers: Record<string, string> = {
      Accept: "application/json",
    };

    if (authToken) {
      headers["Authorization"] = `Bearer ${authToken}`;
    }

    const response = await fetch(endpoint, {
      method: "POST",
      body: formData,
      headers,
    });

    if (!response.ok) {
      if (response.status === 413) {
        const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
        return {
          success: false,
          error: `Payload Limit Exceeded (413): The uploaded binary (${sizeMb} MB) exceeds Vercel's 4.5 MB Function request payload limit. Client-side PE headers, section entropy, and SHA-256 fingerprinting remain fully intact in your inspection report. For cloud ML scanning of files > 4.5 MB up to 10 MB, direct storage upload or a dedicated backend service is recommended.`,
        };
      }
      const errText = await response.text();
      return {
        success: false,
        error: `FastAPI error (${response.status}): ${errText || response.statusText}`,
      };
    }

    const data: FastAPIScanResponse = await response.json();
    return {
      success: true,
      data,
    };
  } catch (err: unknown) {
    return {
      success: false,
      error: `Network failure while dispatching binary: ${(err as Error).message}`,
    };
  }
}

export interface DashboardTelemetry {
  total_scans: number;
  threats_detected: number;
  suspicious_files: number;
  clean_files: number;
  inconclusive_files: number;
  recent_scans: Array<{
    id: string;
    fileName: string;
    fileSize: string;
    sha256: string;
    verdict: string;
    scannedAt: string;
    type: string;
    clamav: string;
    mlPrediction?: string;
    mlConfidence?: number;
  }>;
  threat_distribution: {
    malicious: number;
    suspicious: number;
    clean: number;
    inconclusive: number;
  };
}

export interface PersistedScanItem {
  id: string;
  user_id: string;
  file_name: string;
  file_size_bytes: number;
  formatted_size: string;
  sha256: string;
  sha1?: string;
  md5?: string;
  verdict: "MALICIOUS" | "SUSPICIOUS" | "NO_THREAT_DETECTED" | "INCONCLUSIVE";
  verdict_reasons: string[];
  pe_summary: {
    status?: string;
    machine?: string;
    subsystem?: string;
    number_of_sections?: number;
    file_entropy?: number;
    imported_dlls_count?: number;
    total_imports_count?: number;
    exported_functions_count?: number;
    suspicious_indicators_count?: number;
  };
  clamav_status: string;
  clamav_available: boolean;
  clamav_matched: boolean;
  clamav_signature?: string | null;
  clamav_message?: string;
  ml_status: string;
  ml_available: boolean;
  ml_prediction?: string | null;
  ml_confidence_score?: number | null;
  ml_message?: string;
  created_at: string;
}

/**
 * Fetches dashboard aggregate telemetry for the authenticated user.
 */
export async function fetchDashboardMetrics(
  authToken?: string
): Promise<{ success: boolean; data?: DashboardTelemetry; error?: string }> {
  const endpoint = `${FASTAPI_BASE_URL}/api/v1/scans/dashboard/metrics`;
  try {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (authToken) headers["Authorization"] = `Bearer ${authToken}`;

    const res = await fetch(endpoint, { method: "GET", headers });
    if (!res.ok) {
      return { success: false, error: `Failed to fetch dashboard metrics (${res.status})` };
    }
    const data: DashboardTelemetry = await res.json();
    return { success: true, data };
  } catch (err: unknown) {
    return { success: false, error: `Network error: ${(err as Error).message}` };
  }
}

/**
 * Fetches scan history with optional search and verdict filtering.
 */
export async function fetchUserScans(
  authToken?: string,
  options?: { limit?: number; search?: string; verdict?: string }
): Promise<{ success: boolean; data?: PersistedScanItem[]; error?: string }> {
  const params = new URLSearchParams();
  if (options?.limit) params.set("limit", String(options.limit));
  if (options?.search) params.set("search", options.search);
  if (options?.verdict) params.set("verdict", options.verdict);

  const endpoint = `${FASTAPI_BASE_URL}/api/v1/scans?${params.toString()}`;
  try {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (authToken) headers["Authorization"] = `Bearer ${authToken}`;

    const res = await fetch(endpoint, { method: "GET", headers });
    if (!res.ok) {
      return { success: false, error: `Failed to fetch scans (${res.status})` };
    }
    const data: PersistedScanItem[] = await res.json();
    return { success: true, data };
  } catch (err: unknown) {
    return { success: false, error: `Network error: ${(err as Error).message}` };
  }
}

/**
 * Retrieves a single scan record with full details by scan ID.
 */
export async function fetchScanDetail(
  scanId: string,
  authToken?: string
): Promise<{ success: boolean; data?: PersistedScanItem; error?: string }> {
  const endpoint = `${FASTAPI_BASE_URL}/api/v1/scans/${scanId}`;
  try {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (authToken) headers["Authorization"] = `Bearer ${authToken}`;

    const res = await fetch(endpoint, { method: "GET", headers });
    if (!res.ok) {
      return { success: false, error: `Scan not found or unauthorized (${res.status})` };
    }
    const data: PersistedScanItem = await res.json();
    return { success: true, data };
  } catch (err: unknown) {
    return { success: false, error: `Network error: ${(err as Error).message}` };
  }
}

/**
 * Safely tests ClamAV signature detection using the standard EICAR string.
 */
export async function testEicarDetection(
  authToken?: string
): Promise<{ success: boolean; data?: Record<string, unknown>; error?: string }> {
  const endpoint = `${FASTAPI_BASE_URL}/api/v1/scans/test-eicar`;
  try {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (authToken) headers["Authorization"] = `Bearer ${authToken}`;

    const res = await fetch(endpoint, { method: "POST", headers });
    if (!res.ok) {
      return { success: false, error: `EICAR test failed (${res.status})` };
    }
    const data = await res.json();
    return { success: true, data };
  } catch (err: unknown) {
    return { success: false, error: `Network error: ${(err as Error).message}` };
  }
}


