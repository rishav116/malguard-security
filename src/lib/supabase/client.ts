import { createBrowserClient } from "@supabase/ssr";
import { getSupabaseConfig } from "./config";

export function createClient() {
  const { url, anonKey, isConfigured } = getSupabaseConfig();

  if (!isConfigured) {
    // Return a dummy fallback client so the frontend does not crash if env is missing
    return createBrowserClient(
      url || "https://placeholder-project.supabase.co",
      anonKey || "placeholder-anon-key"
    );
  }

  return createBrowserClient(url, anonKey);
}

export const supabase = createClient();

