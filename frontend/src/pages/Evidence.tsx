import { useState } from "react";

import {
  SearchCheck,
  ShieldAlert,
  FileCode,
  Terminal,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";

import { useSecurity } from "../context/SecurityContext";
import { statusTone } from "../ui/status";

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="evidence-check" style={{ alignItems: "flex-start" }}>
      <Terminal size={16} />
      <span>
        <strong style={{ color: "#A6B5C8", marginRight: 8 }}>{label}:</strong>
        <code>{value}</code>
      </span>
    </div>
  );
}

function Evidence() {
  const { findings, loading, backendUp, error } = useSecurity();

  // No effect needed: fall back to the first finding until one is picked.
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const finding =
    findings.find((item) => item.id === selectedId) ?? findings[0];

  if (backendUp === false) {
    return (
      <div className="page-container">
        <div className="backend-banner">
          <AlertTriangle size={17} />
          {error ?? "Backend unavailable. Please ensure the PATCHPROOF backend is running."}
        </div>
      </div>
    );
  }

  if (loading || !finding) {
    return (
      <div className="page-container">
        <h2>Security Evidence</h2>
        <p>{loading ? "Loading evidence from backend..." : "No findings available."}</p>
      </div>
    );
  }

  const ev = finding.evidence;
  const isIdor = finding.type === "IDOR";
  const code = finding.vulnerable_code;
  const result = finding.verify?.message ?? ev.result ?? "";

  return (
    <div className="page-container">

      <div className="page-title-row">
        <div>
          <h2>Security Evidence</h2>
          <p>Actual evidence captured by the Person 1 scanner for each finding.</p>
        </div>

        <div className="findings-count">
          <SearchCheck size={17} />
          Evidence Viewer
        </div>
      </div>

      <div className="evidence-section">
        <div className="evidence-heading">
          <ShieldAlert size={19} />
          <h3>Select Vulnerability</h3>
        </div>

        <select
          value={finding.id}
          onChange={(e) => setSelectedId(e.target.value)}
          className="evidence-select"
        >
          {findings.map((item) => (
            <option key={item.id} value={item.id}>
              {item.id} · {item.displayName}
            </option>
          ))}
        </select>
      </div>

      <div className="evidence-overview">
        <div className="evidence-icon">
          <ShieldAlert size={23} />
        </div>

        <div>
          <span className="evidence-id">
            {finding.id} · {finding.severity.toUpperCase()} SEVERITY
          </span>
          <h3>{finding.displayName}</h3>
          <p>{finding.file} · Line {finding.line ?? "?"}</p>
        </div>

        <span className={`status ${statusTone(finding.uiStatus)}`}>
          {finding.uiStatus}
        </span>
      </div>

      {/* WHY VULNERABLE */}
      <div className="evidence-section">
        <div className="evidence-heading">
          <AlertTriangle size={18} />
          <h3>Why is this vulnerable?</h3>
        </div>
        <p>{finding.description}</p>
      </div>

      {/* ATTACK EVIDENCE */}
      <div className="evidence-section">
        <div className="evidence-heading">
          <Terminal size={18} />
          <h3>Attack Evidence</h3>
        </div>

        <Row label="Type" value={finding.type} />
        <Row label="Severity" value={finding.severity} />
        {ev.endpoint && (
          <Row label="Endpoint" value={`${ev.method ?? "GET"} ${ev.endpoint}`} />
        )}
        {ev.parameter && <Row label="Parameter" value={ev.parameter} />}
        {isIdor && ev.attacker && (
          <Row label="Attacker" value={ev.attacker.username} />
        )}
        {isIdor && ev.victim_id !== undefined && (
          <Row label="Victim" value={`user id ${ev.victim_id}`} />
        )}
        {ev.payload && <Row label="Attack payload" value={ev.payload} />}
        {result && <Row label="Observed result" value={result} />}
      </div>

      {/* VULNERABLE CODE */}
      <div className="evidence-section">
        <div className="evidence-heading">
          <FileCode size={18} />
          <h3>Vulnerable Code</h3>
        </div>

        <div className="code-header">
          <span>{finding.file}</span>
          <span>Python</span>
        </div>

        <div className="code-block">
          {code.split("\n").map((line, index) => (
            <div className="code-line vulnerable-line" key={index}>
              <span>{finding.line !== null ? finding.line + index : index + 1}</span>
              <code>{line}</code>
            </div>
          ))}
        </div>

        <div className="warning-note">
          <AlertTriangle size={16} />
          <span>Reported by the scanner at {finding.file}:{finding.line ?? "?"}.</span>
        </div>
      </div>

      {/* LIVE PROOF */}
      <div className="evidence-section verification-note">
        <div className="evidence-heading">
          <CheckCircle2 size={19} />
          <h3>Live Exploit Proof</h3>
        </div>

        {finding.verify ? (
          <>
            <div className="evidence-check">
              <CheckCircle2 size={17} />
              <span>
                Backend replay status: <strong>{finding.verify.status}</strong>
                {finding.verify.status === "FAIL" ? " (exploitable)" : ""}
              </span>
            </div>
            {finding.verify.details?.attack_http_status !== undefined && (
              <div className="evidence-check">
                <CheckCircle2 size={17} />
                <span>Attack HTTP status: {finding.verify.details.attack_http_status}</span>
              </div>
            )}
            {finding.verify.details?.attack_records !== undefined && (
              <div className="evidence-check">
                <CheckCircle2 size={17} />
                <span>
                  Records returned — baseline {finding.verify.details.baseline_records},
                  attack {finding.verify.details.attack_records}
                </span>
              </div>
            )}
          </>
        ) : (
          <p className="evidence-disclaimer">
            Run a scan to capture live exploit proof from the backend.
          </p>
        )}
      </div>

      <footer>
        PATCHPROOF <span>·</span> Security Remediation Platform
        <span className="footer-right">Live evidence · Backend data</span>
      </footer>

    </div>
  );
}

export default Evidence;
