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
  clamavState?: "online" | "starting" | "offline" | "failed";
  clamavDesc?: string;
  clamavVersion?: string;
  isWarmingUp?: boolean;
  containerUptimeSec?: number;
  isReadyForScan?: boolean;
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

// Reusable active endpoint cache
let _lastKnownHealthyEndpoint: string | null = null;
let _lastHealthStatus: DetectionEngineStatus | null = null;
let _lastHealthCheckTime = 0;

function getFastApiCandidates(): string[] {
  const configured = process.env.NEXT_PUBLIC_FASTAPI_URL?.trim().replace(/\/+$/, "");
  const isLocalhost =
    typeof window !== "undefined" &&
    (window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1" ||
      window.location.hostname === "0.0.0.0");

  const candidates: string[] = [];

  // Prioritize last known working endpoint if available
  if (_lastKnownHealthyEndpoint) {
    candidates.push(_lastKnownHealthyEndpoint);
  }

  // Same-origin Next.js proxy route (works seamlessly on Vercel and local Next.js without Mixed Content or CORS)
  if (typeof window !== "undefined" && window.location.origin) {
    candidates.push(window.location.origin);
  }

  if (configured) {
    candidates.push(configured);
  }

  if (isLocalhost || !configured) {
    candidates.push("http://127.0.0.1:8000");
    candidates.push("http://localhost:8000");
  }

  return Array.from(new Set(candidates));
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
 * Includes short-term caching and adaptive retries to eliminate transient blips.
 */
export async function checkDetectionEngineHealth(forceRefresh = false): Promise<DetectionEngineStatus> {
  const now = Date.now();
  if (!forceRefresh && _lastHealthStatus && (now - _lastHealthCheckTime < 2000)) {
    return _lastHealthStatus;
  }

  const urls = getFastApiCandidates();
  const startTime = performance.now();
  const timestamp = new Date().toLocaleTimeString();

  for (const baseUrl of urls) {
    const healthEndpoints = [`${baseUrl}/api/v1/health`, `${baseUrl}/health`];

    for (const endpoint of healthEndpoints) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(endpoint, {
          method: "GET",
          headers: {
            Accept: "application/json",
          },
          signal: controller.signal,
          cache: "no-store",
        });

        clearTimeout(timeoutId);
        const latencyMs = Math.round(performance.now() - startTime);

        if (response.ok) {
          const data = await response.json();
          const clamavDaemonDesc = data.engines?.clamav_daemon || "";
          const diag = data.diagnostics || {};
          const uptime = typeof diag.container_uptime_sec === "number" ? diag.container_uptime_sec : 0;
          
          const descLower = clamavDaemonDesc.toLowerCase();
          const isStarting = 
            descLower.includes("starting") || 
            descLower.includes("initializing") ||
            diag.flags?.starting === true;
          const isOnline = 
            descLower.includes("online") || 
            diag.clamav_socket?.ping_ok === true;
          const isFailed = 
            descLower.includes("failed") || 
            diag.flags?.failed === true;

          let clamavState: "online" | "starting" | "offline" | "failed" = "offline";
          let isWarmingUp = false;
          let isReadyForScan = true;
          let displayMessage = "Detection Engine is online and ready for binary classification.";

          if (isStarting) {
            clamavState = "starting";
            isWarmingUp = true;
            isReadyForScan = false;
            displayMessage = `Initializing Security Engine: Loading official ClamAV signature database into memory (${uptime.toFixed(1)}s elapsed; ready in ~15-20s)...`;
          } else if (isOnline) {
            clamavState = "online";
            isWarmingUp = false;
            isReadyForScan = true;
            displayMessage = `Security engines verified: ${clamavDaemonDesc}`;
          } else if (isFailed) {
            clamavState = "failed";
            isWarmingUp = false;
            isReadyForScan = false;
            displayMessage = "ClamAV engine encountered a startup error.";
          }

          _lastKnownHealthyEndpoint = baseUrl;
          const statusResult: DetectionEngineStatus = {
            connected: true,
            endpoint: baseUrl,
            message: displayMessage,
            version: data.version || "1.0.0",
            supportedEngines: [
              "Random Forest PE Classifier",
              "ClamAV Signature Engine",
              "Gemini Security Reasoner",
            ],
            latencyMs,
            lastChecked: timestamp,
            clamavState,
            clamavDesc: clamavDaemonDesc,
            clamavVersion: diag.clamav_socket?.version || data.engines?.clamav_daemon,
            isWarmingUp,
            containerUptimeSec: uptime,
            isReadyForScan,
          };

          _lastHealthStatus = statusResult;
          _lastHealthCheckTime = now;
          return statusResult;
        }
      } catch {
        continue;
      }
    }
  }

  const offlineStatus: DetectionEngineStatus = {
    connected: false,
    endpoint: _lastKnownHealthyEndpoint || FASTAPI_BASE_URL,
    message: "Detection Engine Not Connected (FastAPI backend is offline)",
    lastChecked: timestamp,
  };
  _lastHealthStatus = offlineStatus;
  _lastHealthCheckTime = now;
  return offlineStatus;
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
  // Resolve valid Supabase auth token
  let resolvedToken = authToken;
  if (!resolvedToken) {
    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (session?.access_token) {
        resolvedToken = session.access_token;
        const nowSec = Math.floor(Date.now() / 1000);
        if (session.expires_at && session.expires_at <= nowSec + 30) {
          const { data: refreshed } = await supabase.auth.refreshSession();
          if (refreshed?.session?.access_token) {
            resolvedToken = refreshed.session.access_token;
          }
        }
      }
    } catch {
      // Proceed with provided or fallback token
    }
  }

  // Determine candidate URLs (prioritizing last known healthy endpoint)
  const health = await checkDetectionEngineHealth();
  const rawCandidates = health.connected && health.endpoint
    ? [health.endpoint, ...getFastApiCandidates()]
    : getFastApiCandidates();
  const candidateUrls = Array.from(new Set(rawCandidates));

  let lastErrorMessage = "Detection Engine Not Connected. FastAPI detection backend is offline.";

  for (const baseUrl of candidateUrls) {
    const endpoint = `${baseUrl}/api/v1/scan`;

    try {
      // For files > 4.0 MB (up to 10 MB), direct upload to private Supabase Storage bypasses Vercel's 4.5 MB Function payload limit
      if (file.size > 4.0 * 1024 * 1024) {
        try {
          const storagePath = `${Date.now()}_${Math.random().toString(36).substring(2, 9)}_${file.name.replace(/[^a-zA-Z0-9._-]/g, "_")}`;
          const { data: uploadData, error: uploadError } = await supabase.storage
            .from("malguard-quarantine")
            .upload(storagePath, file, { upsert: false });

          if (!uploadError && uploadData) {
            const storageEndpoint = `${baseUrl}/api/v1/scan/storage`;
            const storageHeaders: Record<string, string> = {
              "Content-Type": "application/json",
              Accept: "application/json",
            };
            if (resolvedToken) {
              storageHeaders["Authorization"] = `Bearer ${resolvedToken}`;
            }

            let storageResp = await fetch(storageEndpoint, {
              method: "POST",
              headers: storageHeaders,
              body: JSON.stringify({
                storage_path: storagePath,
                file_name: file.name,
                sha256: metadata.sha256,
              }),
            });

            if (storageResp.status === 401) {
              try {
                const { data: refreshed } = await supabase.auth.refreshSession();
                if (refreshed?.session?.access_token) {
                  resolvedToken = refreshed.session.access_token;
                  storageHeaders["Authorization"] = `Bearer ${resolvedToken}`;
                  storageResp = await fetch(storageEndpoint, {
                    method: "POST",
                    headers: storageHeaders,
                    body: JSON.stringify({
                      storage_path: storagePath,
                      file_name: file.name,
                      sha256: metadata.sha256,
                    }),
                  });
                }
              } catch {}
            }

            if (storageResp.ok) {
              const data: FastAPIScanResponse = await storageResp.json();
              _lastKnownHealthyEndpoint = baseUrl;
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

      if (resolvedToken) {
        headers["Authorization"] = `Bearer ${resolvedToken}`;
      }

      let response = await fetch(endpoint, {
        method: "POST",
        body: formData,
        headers,
      });

      // 401 handling with proactive session refresh
      if (response.status === 401) {
        try {
          const { data: refreshed } = await supabase.auth.refreshSession();
          if (refreshed?.session?.access_token && refreshed.session.access_token !== resolvedToken) {
            resolvedToken = refreshed.session.access_token;
            headers["Authorization"] = `Bearer ${resolvedToken}`;
            response = await fetch(endpoint, {
              method: "POST",
              body: formData,
              headers,
            });
          }
        } catch {}

        if (response.status === 401) {
          return {
            success: false,
            error: "Authentication required. Please sign in to your MALGUARD AI account to run binary scans and save threat reports.",
          };
        }
      }

      if (!response.ok) {
        if (response.status === 413) {
          const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
          return {
            success: false,
            error: `Payload Limit Exceeded (413): The uploaded binary (${sizeMb} MB) exceeds Vercel's 4.5 MB Function request payload limit. Client-side PE headers, section entropy, and SHA-256 fingerprinting remain fully intact in your inspection report. For cloud ML scanning of files > 4.5 MB up to 10 MB, direct storage upload or a dedicated backend service is recommended.`,
          };
        }
        const errText = await response.text();
        let parsedDetail = errText || response.statusText;
        try {
          const parsed = JSON.parse(errText);
          parsedDetail = parsed.detail || parsedDetail;
        } catch {}
        return {
          success: false,
          error: `FastAPI error (${response.status}): ${parsedDetail}`,
        };
      }

      const data: FastAPIScanResponse = await response.json();
      _lastKnownHealthyEndpoint = baseUrl;
      return {
        success: true,
        data,
      };
    } catch (err: unknown) {
      lastErrorMessage = `Network failure while dispatching binary to ${baseUrl}: ${(err as Error).message}`;
      continue;
    }
  }

  return {
    success: false,
    error: lastErrorMessage,
  };
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


