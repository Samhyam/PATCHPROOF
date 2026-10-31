import type { UiStatus } from "../context/SecurityContext";

/** Maps a UI status to a `.status.<tone>` CSS modifier (see App.css). */
export function statusTone(status: UiStatus): string {
  switch (status) {
    case "PATCH VERIFIED":
      return "verified";
    case "Exploit confirmed":
      return "exploited";
    case "Verification failed":
    case "Scan error":
      return "failed";
    case "Not exploitable":
    case "Not reproduced":
      return "info";
    case "Scanning":
    case "Remediating":
      return "scanning";
    default:
      return "pending";
  }
}

/** Human severity label -> `.severity.<tone>` (only `high` exists today). */
export function severityTone(severity: string): string {
  const s = severity.toLowerCase();
  return s === "high" || s === "critical" ? "high" : "high";
}
