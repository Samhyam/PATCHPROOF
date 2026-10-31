import {
  SearchCheck,
  ShieldCheck,
  Bug,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  TerminalSquare,
} from "lucide-react";

import { useSecurity } from "../context/SecurityContext";

function ScanTerminal({
  lines,
  running,
  runId,
}: {
  lines: string[];
  running: boolean;
  runId: number;
}) {
  return (
    <div className="scan-terminal" key={runId}>
      <div className="scan-terminal-bar">
        <span className="term-dot red" />
        <span className="term-dot amber" />
        <span className="term-dot green" />
        <span className="scan-terminal-title">
          <TerminalSquare size={13} /> person1@patchproof — live source-code scan
        </span>
      </div>
      <div className="scan-terminal-body">
        {lines.map((line, i) => (
          <div
            className="scan-terminal-line"
            style={{ animationDelay: `${Math.min(i * 0.05, 2)}s` }}
            key={i}
          >
            <span className="term-prompt">›</span>
            {line}
          </div>
        ))}
        {running && (
          <div className="scan-terminal-line">
            <span className="term-prompt">›</span>
            <span className="term-cursor">▋</span>
          </div>
        )}
      </div>
    </div>
  );
}

function Scan() {
  const {
    findings,
    scan,
    scanning,
    scanned,
    scanSource,
    scanLog,
    scanRunId,
    backendUp,
    error,
    health,
  } = useSecurity();

  const confirmed = findings.filter((f) => f.exploited).length;

  return (
    <div className="page-container">

      <div className="page-heading">
        <div>
          <p className="breadcrumb">WORKSPACE / SCAN</p>
          <h1>Application Security Scan</h1>
          <p className="subtitle">
            Replay each finding's attack against the live app through the backend
            and confirm it is actually exploitable.
          </p>
        </div>

        <button className="scan-button" onClick={() => void scan()} disabled={scanning}>
          {scanning ? <Loader2 size={18} /> : <SearchCheck size={18} />}
          {scanning ? "Scanning..." : "Run Live Scan"}
        </button>
      </div>

      {backendUp === false && (
        <div className="backend-banner">
          <AlertTriangle size={17} />
          {error ?? "Backend unavailable. Please ensure the PATCHPROOF backend is running."}
        </div>
      )}

      {backendUp && health && (
        <div className="backend-banner ok">
          <CheckCircle2 size={17} />
          Backend connected · target: {health.target_dir}
        </div>
      )}

      <div className="patch-main-card">
        <div className="evidence-heading">
          <ShieldCheck size={22} />
          <h3>Dynamic Security Scanner</h3>
          {(scanning || scanSource === "live") && (
            <span className="live-pill">● LIVE</span>
          )}
        </div>

        <p>
          Person 1 analyzes the application's actual source code, discovers the
          vulnerabilities, and <strong>proves</strong> each one by running the real
          attack. Nothing here is simulated.
        </p>

        {(scanning || scanLog.length > 0) && (
          <ScanTerminal lines={scanLog} running={scanning} runId={scanRunId} />
        )}

        {scanned && !scanning && (
          <div className="verification-message success-message">
            <CheckCircle2 size={17} />
            Scan complete · {confirmed} of {findings.length} findings confirmed exploitable.
            {scanSource === "live"
              ? " Discovered live by the Person 1 scanner (source-code analysis)."
              : scanSource === "samples"
              ? " (Scanner service offline — using backend findings.)"
              : ""}
          </div>
        )}
      </div>

      {findings.length > 0 && (
        <>
          <div className="section-heading">
            <div>
              <h2>Scan Results</h2>
              <p>Dynamic exploit confirmation per finding</p>
            </div>
          </div>

          <div className="patch-summary">
            <div className="stat-card">
              <span>Total Findings</span>
              <strong className="stat-value">
                {String(findings.length).padStart(2, "0")}
              </strong>
              <small>Detected vulnerabilities</small>
            </div>

            <div className="stat-card">
              <span>Exploit Confirmed</span>
              <strong className="stat-value danger-text">
                {String(confirmed).padStart(2, "0")}
              </strong>
              <small>Proven exploitable live</small>
            </div>
          </div>

          <div className="verification-list">
            {findings.map((finding) => {
              const v = finding.verify;
              return (
                <div className="verification-card" key={finding.id}>
                  <div className="verification-card-top">
                    <div className="verification-icon">
                      <Bug size={21} />
                    </div>

                    <div className="verification-details">
                      <h3>{finding.displayName}</h3>
                      <p>{finding.description}</p>
                      <small>
                        {finding.id} · {finding.file} : {finding.line ?? "?"}
                      </small>
                    </div>

                    {finding.busy ? (
                      <Loader2 size={19} color="#E8A34A" />
                    ) : finding.exploited ? (
                      <AlertTriangle size={19} color="#F08B9A" />
                    ) : v ? (
                      <CheckCircle2 size={19} color="#71D4AC" />
                    ) : (
                      <SearchCheck size={19} color="#78B5FF" />
                    )}
                  </div>

                  {finding.busy && (
                    <div className="verification-message">
                      <Loader2 size={15} />
                      Replaying attack with payload{" "}
                      <code>{String(finding.evidence.payload ?? "")}</code>...
                    </div>
                  )}

                  {!finding.busy && v?.status === "FAIL" && (
                    <div className="verification-message failure-message">
                      <AlertTriangle size={15} />
                      EXPLOITABLE — {v.message}
                      {v.details?.attack_records !== undefined && (
                        <>
                          {" "}(baseline {v.details.baseline_records} →
                          attack {v.details.attack_records} records)
                        </>
                      )}
                    </div>
                  )}

                  {!finding.busy && v?.status === "PASS" && (
                    <div className="verification-message success-message">
                      <CheckCircle2 size={15} />
                      Not exploitable — {v.message}
                    </div>
                  )}

                  {!finding.busy && v?.status === "ERROR" && (
                    <div className="verification-message failure-message">
                      <XCircle size={15} />
                      Scan error — {v.message}
                    </div>
                  )}

                  {!finding.busy && !v && (
                    <div className="verification-message">
                      <SearchCheck size={15} />
                      Run the live scan to confirm exploitability.
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}

      <footer>
        PATCHPROOF <span>·</span> Security Remediation Platform
        <span className="footer-right">Live scan · Backend /verify</span>
      </footer>

    </div>
  );
}

export default Scan;
