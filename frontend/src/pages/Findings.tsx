import {
  Bug,
  ShieldAlert,
  FileCode,
  CheckCircle2,
  Clock,
  Loader2,
  AlertTriangle,
} from "lucide-react";

import { useSecurity } from "../context/SecurityContext";
import { statusTone } from "../ui/status";

function Findings() {
  const { findings, loading, error, backendUp } = useSecurity();

  const highSeverity = findings.filter(
    (f) => f.severity.toLowerCase() === "high"
  ).length;

  const verified = findings.filter((f) => f.verified).length;

  return (
    <div className="page-container">

      <div className="page-title-row">
        <div>
          <h2>Security Findings</h2>
          <p>Live findings produced by the Person 1 scanner, served by the backend.</p>
        </div>

        <div className="findings-count">
          <Bug size={17} />
          {findings.length} Findings
        </div>
      </div>

      {backendUp === false && (
        <div className="backend-banner">
          <AlertTriangle size={17} />
          {error ?? "Backend unavailable. Please ensure the PATCHPROOF backend is running."}
        </div>
      )}

      {loading ? (
        <div className="verification-message">
          <Loader2 size={16} />
          Loading findings from backend...
        </div>
      ) : (
        <>
          <div className="findings-summary">
            <div>
              <span>Total Findings</span>
              <strong>{String(findings.length).padStart(2, "0")}</strong>
            </div>

            <div>
              <span>High Severity</span>
              <strong className="danger-text">
                {String(highSeverity).padStart(2, "0")}
              </strong>
            </div>

            <div>
              <span>Verified Fixes</span>
              <strong className="success-text">
                {String(verified).padStart(2, "0")}
              </strong>
            </div>
          </div>

          <div className="finding-list">
            {findings.map((finding) => (
              <div className="finding-card" key={finding.id}>

                <div className="finding-card-top">
                  <div className="finding-title">
                    <div className="finding-card-icon">
                      <ShieldAlert size={20} />
                    </div>

                    <div>
                      <h3>{finding.displayName}</h3>
                      <span>
                        {finding.id}
                        {" · "}
                        {finding.type}
                      </span>
                    </div>
                  </div>

                  <span className="severity high">{finding.severity}</span>
                </div>

                <p className="finding-description">{finding.description}</p>

                <div className="finding-card-bottom">
                  <span>
                    <FileCode size={15} />
                    {finding.file} : {finding.line ?? "?"}
                  </span>

                  <span className={`status ${statusTone(finding.uiStatus)}`}>
                    {finding.uiStatus === "PATCH VERIFIED" ? (
                      <CheckCircle2 size={13} style={{ marginRight: 5 }} />
                    ) : finding.busy ? (
                      <Loader2 size={13} style={{ marginRight: 5 }} />
                    ) : (
                      <Clock size={13} style={{ marginRight: 5 }} />
                    )}
                    {finding.uiStatus}
                  </span>
                </div>
              </div>
            ))}

            {!loading && findings.length === 0 && backendUp !== false && (
              <div className="verification-message">
                <AlertTriangle size={15} />
                No findings returned by the backend.
              </div>
            )}
          </div>
        </>
      )}

      <footer>
        PATCHPROOF <span>·</span> Security Remediation Platform
        <span className="footer-right">
          Live findings · Person 1 → backend
        </span>
      </footer>

    </div>
  );
}

export default Findings;
