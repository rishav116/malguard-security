/**
 * Supabase Configuration Utility
 * Checks whether valid Supabase credentials have been configured in environment variables.
 */

export const getSupabaseConfig = () => {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
  const anonKey =
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    "";

  // Check if credentials exist and are not placeholder values
  const isConfigured =
    Boolean(url) &&
    Boolean(anonKey) &&
    !url.includes("your-project-id") &&
    !anonKey.includes("your-anon-key") &&
    !anonKey.includes("your-publishable-key");

  return {
    url,
    anonKey,
    isConfigured,
  };
};

