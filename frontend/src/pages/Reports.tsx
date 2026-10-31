import {
  FileText,
  ShieldCheck,
  Bug,
  Code2,
  CheckCircle2,
  Download,
  CalendarDays,
  AlertTriangle,
} from "lucide-react";

import { useSecurity } from "../context/SecurityContext";
import { statusTone } from "../ui/status";

function Reports() {
  const { findings, backendUp, error, health } = useSecurity();

  const total = findings.length;
  const applied = findings.filter((f) => f.patchApplied).length;
  const verified = findings.filter((f) => f.verified).length;
  const failed = findings.filter((f) => f.remediation && !f.verified).length;

  const bySeverity = (sev: string) =>
    findings.filter((f) => f.severity.toLowerCase() === sev).length;

  const patchProgress = total ? (applied / total) * 100 : 0;
  const verificationProgress = total ? (verified / total) * 100 : 0;

  return (
    <div className="page-container">

      <div className="page-heading">
        <div>
          <p className="breadcrumb">WORKSPACE / REPORTS</p>
          <h1>Security Reports</h1>
          <p className="subtitle">
            Project security status derived from live findings and remediation.
          </p>
        </div>

        <button className="scan-button" onClick={() => window.print()}>
          <Download size={17} />
          Export Report
        </button>
      </div>

      {backendUp === false && (
        <div className="backend-banner">
          <AlertTriangle size={17} />
          {error ?? "Backend unavailable. Please ensure the PATCHPROOF backend is running."}
        </div>
      )}

      <div className="section-heading">
        <div>
          <h2>Project Security Summary</h2>
          <p>Calculated from actual backend data.</p>
        </div>
      </div>

      <div className="report-summary-grid">
        <div className="stat-card">
          <div className="stat-top">
            <span>Total Findings</span>
            <Bug size={19} />
          </div>
          <strong className="stat-value">{String(total).padStart(2, "0")}</strong>
          <small>Vulnerabilities identified</small>
        </div>

        <div className="stat-card">
          <div className="stat-top">
            <span>Patches Applied</span>
            <Code2 size={19} />
          </div>
          <strong className="stat-value">{String(applied).padStart(2, "0")}</strong>
          <small>Fixes written to disk</small>
        </div>

        <div className="stat-card">
          <div className="stat-top">
            <span>Verified Fixes</span>
            <ShieldCheck size={19} />
          </div>
          <strong className="stat-value success-text">
            {String(verified).padStart(2, "0")}
          </strong>
          <small>PATCH_VERIFIED</small>
        </div>

        <div className="stat-card">
          <div className="stat-top">
            <span>Failed</span>
            <AlertTriangle size={19} />
          </div>
          <strong className="stat-value danger-text">
            {String(failed).padStart(2, "0")}
          </strong>
          <small>Did not verify</small>
        </div>
      </div>

      <div className="report-main-card">
        <div className="report-card-heading">
          <div className="report-icon">
            <FileText size={22} />
          </div>
          <div>
            <h2>Security Assessment Report</h2>
            <p>Target: {health?.target_dir ?? "—"}</p>
          </div>
        </div>

        <div className="report-divider" />

        <h3>Severity Breakdown</h3>
        <div className="report-progress-item">
          <div>
            <span>High</span>
            <strong>{bySeverity("high")}</strong>
          </div>
        </div>
        {bySeverity("medium") > 0 && (
          <div className="report-progress-item">
            <div><span>Medium</span><strong>{bySeverity("medium")}</strong></div>
          </div>
        )}
        {bySeverity("low") > 0 && (
          <div className="report-progress-item">
            <div><span>Low</span><strong>{bySeverity("low")}</strong></div>
          </div>
        )}

        <div className="report-divider" />

        <h3>Identified Vulnerabilities</h3>
        {findings.map((finding) => (
          <div className="report-finding" key={finding.id}>
            <div>
              <strong>{finding.displayName}</strong>
              <small>{finding.id} · {finding.file} · Line {finding.line ?? "?"}</small>
            </div>
            <span className={`status ${statusTone(finding.uiStatus)}`}>
              {finding.uiStatus}
            </span>
          </div>
        ))}

        <div className="report-divider" />

        <h3>Remediation Summary</h3>

        <div className="report-progress-item">
          <div>
            <span>Patches Applied</span>
            <strong>{applied} / {total}</strong>
          </div>
          <div className="report-progress-track">
            <div style={{ width: `${patchProgress}%` }} />
          </div>
        </div>

        <div className="report-progress-item">
          <div>
            <span>Verification Passed</span>
            <strong>{verified} / {total}</strong>
          </div>
          <div className="report-progress-track">
            <div style={{ width: `${verificationProgress}%` }} />
          </div>
        </div>

        <div className="report-note">
          <CheckCircle2 size={17} />
          <p>{verified} of {total} findings reached PATCH_VERIFIED.</p>
        </div>
      </div>

      <div className="report-footer">
        <CalendarDays size={15} />
        <span>PATCHPROOF · Security Remediation Platform</span>
        <span className="report-demo-note">Live report · Backend data</span>
      </div>

    </div>
  );
}

export default Reports;
