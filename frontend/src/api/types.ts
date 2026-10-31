/**
 * TypeScript types that mirror Person 2's REAL backend schema
 * (patch-engine/models.py, verifier.py, pipeline.py). No `any`.
 */

export type VulnType = "SQL_INJECTION" | "IDOR";

export interface Attacker {
  username: string;
  password: string;
}

/** Evidence object produced by Person 1 / stored in findings.
 *  Backend model is extra="allow", so IDOR carries attacker + victim_id. */
export interface Evidence {
  payload?: string;
  result?: string;
  endpoint?: string;
  method?: string;
  parameter?: string;
  attacker?: Attacker;
  victim_id?: number;
  [key: string]: unknown;
}

/** Matches patch-engine/models.py Finding. */
export interface Finding {
  id: string;
  type: VulnType | string;
  severity: string;
  file: string;
  line: number | null;
  description: string;
  vulnerable_code: string;
  evidence: Evidence;
}

export interface HealthResponse {
  status: string;
  target_dir: string;
  supported_types: string[];
  ai_available: boolean;
}

/** GET /samples -> { "<stem>": Finding, ... } */
export type SamplesResponse = Record<string, Finding>;

export type TestStatus = "PASS" | "FAIL" | "ERROR" | "SKIPPED";

/** POST /verify -> run_security_test(...) result. */
export interface SecurityTestResult {
  status: TestStatus;
  payload?: string;
  message?: string;
  details?: {
    endpoint?: string;
    baseline_records?: number;
    attack_records?: number;
    attack_http_status?: number;
    leaked_record_id?: number | null;
  };
  vulnerability_id?: string;
  type?: string;
  /** present inside full_remediation.verification.security_test */
  before?: TestStatus;
  after?: TestStatus | null;
}

export interface RegressionTest {
  name: string;
  status: TestStatus;
  message: string;
}

export interface RegressionResult {
  status: TestStatus;
  tests: RegressionTest[];
  passed: number;
  failed: number;
  skipped: number;
  message?: string;
}

export interface PatchChange {
  removed: string[];
  added: string[];
}

export interface PatchResult {
  status: "APPLIED" | "FAILED" | "ROLLED_BACK" | string;
  file?: string;
  diff?: string;
  method?: string;
  source?: string;
  original_code?: string;
  patched_code?: string;
  changes?: PatchChange[];
  backup?: string | null;
  reason?: string;
  detail?: string;
}

export interface RemediationStep {
  step: number;
  name: string;
  status: string;
  detail: string;
}

export type FinalStatus =
  | "PATCH_VERIFIED"
  | "PATCH_FAILED"
  | "REGRESSION_FAILURE"
  | "NOT_REPRODUCED"
  | "VERIFICATION_ERROR"
  | "INVALID_FINDING";

/** POST /full-remediation -> pipeline.full_remediation(...) result. */
export interface RemediationResult {
  id: string;
  type: string;
  severity: string;
  file: string;
  display: { title: string; severity: string; patch_available: boolean };
  explanation: { source: string; text: string };
  patch: PatchResult | null;
  verification: {
    security_test: SecurityTestResult | null;
    regression_tests: RegressionResult | null;
  };
  steps: RemediationStep[];
  final_status: FinalStatus | null;
  patch_explanation?: { source: string; text: string };
  error?: string;
}
