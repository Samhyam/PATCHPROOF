/**
 * Typed wrappers around the real Person 2 endpoints.
 * Routes (from patch-engine/api.py):
 *   GET  /health
 *   GET  /samples
 *   POST /verify            body: Finding
 *   POST /full-remediation  body: Finding
 *   POST /regression
 *   POST /reset
 */
import { apiClient, ApiError, SCANNER_BASE_URL } from "./client";
import type {
  Finding,
  HealthResponse,
  RegressionResult,
  RemediationResult,
  SamplesResponse,
  SecurityTestResult,
} from "./types";

/** Live source-code scan via the Person 1 scanner service. Discovers and
 *  exploit-proves findings by analyzing the target app's source. */
export async function discoverFindings(): Promise<{
  findings: Finding[];
  target: string;
  log: string;
}> {
  let res: Response;
  try {
    res = await fetch(`${SCANNER_BASE_URL}/scan`);
  } catch {
    throw new ApiError("Scanner service unavailable", 0);
  }
  if (!res.ok) throw new ApiError(`Scanner returned HTTP ${res.status}`, res.status);
  const data = (await res.json()) as { findings: Finding[]; target: string; log?: string };
  if (!Array.isArray(data.findings) || data.findings.length === 0) {
    throw new ApiError("Scanner returned no findings", 0);
  }
  return { findings: data.findings, target: data.target, log: data.log ?? "" };
}

export function getHealth(): Promise<HealthResponse> {
  return apiClient.get<HealthResponse>("/health");
}

/** The findings Person 1 produced, served by Person 2, sorted by id. */
export async function getFindings(): Promise<Finding[]> {
  const samples = await apiClient.get<SamplesResponse>("/samples");
  return Object.values(samples).sort((a, b) => a.id.localeCompare(b.id));
}

/** Live exploit replay against the current code on disk (FAIL = exploitable). */
export function verifyFinding(finding: Finding): Promise<SecurityTestResult> {
  return apiClient.post<SecurityTestResult>("/verify", finding);
}

/** Reproduce -> patch -> replay -> regression -> final_status. */
export function fullRemediation(finding: Finding): Promise<RemediationResult> {
  return apiClient.post<RemediationResult>("/full-remediation", finding);
}

export function runRegression(): Promise<RegressionResult> {
  return apiClient.post<RegressionResult>("/regression");
}

/** Restore the demo app to its original vulnerable state. */
export function resetBackend(): Promise<{ restored: string[] }> {
  return apiClient.post<{ restored: string[] }>("/reset");
}
