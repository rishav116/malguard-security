/**
 * MALGUARD AI - Deterministic Time & Date Formatting Utilities
 * Prevents Next.js SSR hydration mismatches by ensuring identical
 * deterministic casing and format, while providing client-side mounting safety.
 */

/**
 * Formats a Date object or ISO timestamp string into a deterministic 12-hour or 24-hour time.
 * E.g., "10:14 PM" (ensures uppercase AM/PM and fixed 2-digit minutes across Node and browsers).
 */
export function formatDeterministicTime(input?: Date | string | number | null): string {
  if (!input) return "";
  const date = typeof input === "object" && input instanceof Date ? input : new Date(input);
  if (isNaN(date.getTime())) return "";

  const hours = date.getHours();
  const minutes = date.getMinutes().toString().padStart(2, "0");
  const ampm = hours >= 12 ? "PM" : "AM";
  const displayHours = (hours % 12 || 12).toString().padStart(2, "0");

  return `${displayHours}:${minutes} ${ampm}`;
}

/**
 * Formats a Date object or ISO timestamp string into a deterministic YYYY-MM-DD or standard date.
 */
export function formatDeterministicDate(input?: Date | string | number | null): string {
  if (!input) return "";
  const date = typeof input === "object" && input instanceof Date ? input : new Date(input);
  if (isNaN(date.getTime())) return "";

  const year = date.getFullYear();
  const month = (date.getMonth() + 1).toString().padStart(2, "0");
  const day = date.getDate().toString().padStart(2, "0");

  return `${year}-${month}-${day}`;
}

/**
 * Formats a full date-time string deterministically: "YYYY-MM-DD HH:MM AM/PM"
 */
export function formatDeterministicDateTime(input?: Date | string | number | null): string {
  if (!input) return "";
  const date = typeof input === "object" && input instanceof Date ? input : new Date(input);
  if (isNaN(date.getTime())) return "";

  return `${formatDeterministicDate(date)} ${formatDeterministicTime(date)}`;
}

