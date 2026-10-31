/* eslint-disable react-refresh/only-export-components --
   This context module intentionally exports the provider plus the useSecurity
   hook and shared types; that is the idiomatic React context layout. */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

import {
  discoverFindings,
  getFindings,
  getHealth,
  fullRemediation,
  resetBackend,
  verifyFinding,
} from "../api/remediation";
import { ApiError } from "../api/client";
import type {
  Finding,
  HealthResponse,
  RemediationResult,
  SecurityTestResult,
} from "../api/types";

/** UI-facing status derived strictly from real backend state. */
export type UiStatus =
  | "Detected"
  | "Scanning"
  | "Exploit confirmed"
  | "Not exploitable"
  | "Scan error"
  | "Remediating"
  | "PATCH VERIFIED"
  | "Verification failed"
  | "Not reproduced";

/** A backend Finding plus everything we have learned about it from the API. */
export interface FindingView extends Finding {
  displayName: string;
  uiStatus: UiStatus;
  verify?: SecurityTestResult;
  remediation?: RemediationResult;
  exploited: boolean;
  patchApplied: boolean;
  verified: boolean;
  busy: boolean;
  remediationMs?: number;
}

interface SecurityContextType {
  findings: FindingView[];
  health: HealthResponse | null;
  backendUp: boolean | null;
  loading: boolean;
  scanning: boolean;
  scanned: boolean;
  scanSource: "live" | "samples" | null;
  scanLog: string[];
  scanRunId: number;
  error: string | null;
  busyIds: Record<string, string>;
  refresh: () => Promise<void>;
  scan: () => Promise<void>;
  remediate: (id: string) => Promise<void>;
  remediateAll: () => Promise<void>;
  reset: () => Promise<void>;
}

const DISPLAY_NAMES: Record<string, string> = {
  SQL_INJECTION: "SQL Injection",
  IDOR: "IDOR / Broken Access Control",
};

function displayNameFor(finding: Finding): string {
  return DISPLAY_NAMES[finding.type] ?? finding.type;
}

function deriveStatus(
  busyLabel: string | undefined,
  verify: SecurityTestResult | undefined,
  remediation: RemediationResult | undefined
): UiStatus {
  if (busyLabel === "scan") return "Scanning";
  if (busyLabel === "remediate") return "Remediating";

  if (remediation) {
    switch (remediation.final_status) {
      case "PATCH_VERIFIED":
        return "PATCH VERIFIED";
      case "NOT_REPRODUCED":
        return "Not reproduced";
      case null:
        break;
      default:
        return "Verification failed";
    }
  }
  if (verify) {
    if (verify.status === "FAIL") return "Exploit confirmed";
    if (verify.status === "PASS") return "Not exploitable";
    return "Scan error";
  }
  return "Detected";
}

const SecurityContext = createContext<SecurityContextType | undefined>(undefined);

export function SecurityProvider({ children }: { children: ReactNode }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [verifyResults, setVerifyResults] = useState<Record<string, SecurityTestResult>>({});
  const [remediationResults, setRemediationResults] = useState<Record<string, RemediationResult>>({});
  const [remediationMs, setRemediationMs] = useState<Record<string, number>>({});
  const [busyIds, setBusyIds] = useState<Record<string, string>>({});

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [backendUp, setBackendUp] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanned, setScanned] = useState(false);
  const [scanSource, setScanSource] = useState<"live" | "samples" | null>(null);
  const [scanLog, setScanLog] = useState<string[]>([]);
  const [scanRunId, setScanRunId] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const setBusy = (id: string, label: string | null) =>
    setBusyIds((prev) => {
      const next = { ...prev };
      if (label) next[id] = label;
      else delete next[id];
      return next;
    });

  const loadFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [healthResp, list] = await Promise.all([getHealth(), getFindings()]);
      setHealth(healthResp);
      setBackendUp(true);
      setFindings(list);
    } catch (err) {
      setBackendUp(false);
      setError(err instanceof ApiError ? err.message : String(err));
      setFindings([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Legitimate external sync: fetch backend state once on mount.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void loadFindings();
  }, [loadFindings]);

  const refresh = loadFindings;

  /** Real scan: confirm every finding is currently exploitable via /verify. */
  const scan = useCallback(async () => {
    setScanning(true);
    setError(null);
    setScanRunId((n) => n + 1);
    setScanLog([]);
    try {
      const healthResp = await getHealth();
      setHealth(healthResp);
      setBackendUp(true);

      // Prefer a real live source-code scan (Person 1); fall back to samples.
      let list: Finding[];
      try {
        const discovered = await discoverFindings();
        list = discovered.findings;
        setScanSource("live");
        setScanLog(discovered.log.split("\n").filter((l) => l.trim().length > 0));
      } catch {
        list = await getFindings();
        setScanSource("samples");
        setScanLog([
          "[!] Person 1 scanner service offline (http://localhost:8100)",
          "[i] Falling back to findings served by the Person 2 backend",
          `[i] Loaded ${list.length} finding(s) from /samples`,
        ]);
      }
      setFindings(list);
      setVerifyResults({});
      setRemediationResults({});

      for (const finding of list) {
        setBusy(finding.id, "scan");
        try {
          const result = await verifyFinding(finding);
          setVerifyResults((prev) => ({ ...prev, [finding.id]: result }));
        } finally {
          setBusy(finding.id, null);
        }
      }
      setScanned(true);
    } catch (err) {
      setBackendUp(false);
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setScanning(false);
    }
  }, []);

  const remediate = useCallback(
    async (id: string) => {
      const finding = findings.find((f) => f.id === id);
      if (!finding) return;
      setBusy(id, "remediate");
      setError(null);
      const started = performance.now();
      try {
        const result = await fullRemediation(finding);
        setRemediationResults((prev) => ({ ...prev, [id]: result }));
        setRemediationMs((prev) => ({ ...prev, [id]: Math.round(performance.now() - started) }));
      } catch (err) {
        setError(err instanceof ApiError ? err.message : String(err));
      } finally {
        setBusy(id, null);
      }
    },
    [findings]
  );

  const remediateAll = useCallback(async () => {
    for (const finding of findings) {
      await remediate(finding.id);
    }
  }, [findings, remediate]);

  const reset = useCallback(async () => {
    setError(null);
    try {
      await resetBackend();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
    setVerifyResults({});
    setRemediationResults({});
    setRemediationMs({});
    setScanned(false);
    setScanSource(null);
    setScanLog([]);
    await loadFindings();
  }, [loadFindings]);

  const views: FindingView[] = findings.map((finding) => {
    const verify = verifyResults[finding.id];
    const remediation = remediationResults[finding.id];
    const busyLabel = busyIds[finding.id];
    return {
      ...finding,
      displayName: displayNameFor(finding),
      verify,
      remediation,
      busy: Boolean(busyLabel),
      exploited:
        verify?.status === "FAIL" ||
        remediation?.verification.security_test?.before === "FAIL",
      patchApplied: remediation?.patch?.status === "APPLIED",
      verified: remediation?.final_status === "PATCH_VERIFIED",
      uiStatus: deriveStatus(busyLabel, verify, remediation),
      remediationMs: remediationMs[finding.id],
    };
  });

  return (
    <SecurityContext.Provider
      value={{
        findings: views,
        health,
        backendUp,
        loading,
        scanning,
        scanned,
        scanSource,
        scanLog,
        scanRunId,
        error,
        busyIds,
        refresh,
        scan,
        remediate,
        remediateAll,
        reset,
      }}
    >
      {children}
    </SecurityContext.Provider>
  );
}

export function useSecurity() {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error("useSecurity must be used inside SecurityProvider");
  }
  return context;
}
