/**
 * Central HTTP client for the Person 2 backend.
 * The base URL is configured once via VITE_API_BASE_URL (see .env).
 */

export const API_BASE_URL: string =
  (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/+$/, "") ||
  "http://localhost:8000";

/** Person 1 scanner service (live source-code scan). */
export const SCANNER_BASE_URL: string =
  (import.meta.env.VITE_SCANNER_URL as string | undefined)?.replace(/\/+$/, "") ||
  "http://localhost:8100";

/** Error that carries enough context for the UI to show a real message. */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...init,
    });
  } catch {
    // Network error / backend not running / CORS blocked.
    throw new ApiError(
      "Backend unavailable. Please ensure the PATCHPROOF backend is running.",
      0
    );
  }

  const text = await response.text();
  const data = text ? (JSON.parse(text) as unknown) : null;

  if (!response.ok) {
    const detail =
      data && typeof data === "object" && "detail" in data
        ? String((data as { detail: unknown }).detail)
        : `Request failed (HTTP ${response.status})`;
    throw new ApiError(detail, response.status);
  }
  return data as T;
}

export const apiClient = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "POST",
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
};
