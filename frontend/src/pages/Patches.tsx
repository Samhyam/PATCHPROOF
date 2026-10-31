import {
  ShieldCheck,
  Code2,
  CheckCircle2,
  AlertTriangle,
  Minus,
  Plus,
  Loader2,
  PlayCircle,
  Download,
} from "lucide-react";

import { useSecurity } from "../context/SecurityContext";
import type { FindingView } from "../context/SecurityContext";
import { statusTone } from "../ui/status";

function downloadDiff(finding: FindingView) {
  const diff = finding.remediation?.patch?.diff;
  if (!diff) return;
  const blob = new Blob([diff], { type: "text/x-patch" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${finding.id}-${finding.file}.diff`;
  a.click();
  URL.revokeObjectURL(url);
}

function PatchCard({
  finding,
  onRemediate,
}: {
  finding: FindingView;
  onRemediate: (id: string) => void;
}) {
  const patch = finding.remediation?.patch;
  const changes = patch?.changes ?? [];
  const applied = finding.patchApplied;

  return (
    <div className="patch-main-card">

      <div className="patch-card-heading">
        <div className="patch-heading-left">
          <div className="patch-info-icon">
            <Code2 size={21} />
          </div>

          <div>
            <span className="evidence-id">
              {finding.id} · {finding.severity.toUpperCase()} SEVERITY
            </span>
            <h3>{finding.displayName} Fix</h3>
            <p>{finding.file} · Line {finding.line ?? "?"}</p>
          </div>
        </div>

        <span className={`status ${statusTone(finding.uiStatus)}`}>
          {finding.uiStatus}
        </span>
      </div>

      <div className="patch-recommendation">
        <div className="evidence-heading">
          <ShieldCheck size={18} />
          <h3>Recommended Fix</h3>
        </div>
        <p>
          {finding.remediation?.explanation?.text ??
            (finding.type === "IDOR"
              ? "Add an object-level authorization check so a user can only access their own resource."
              : "Replace string-concatenated SQL with a parameterized query so input is treated as data.")}
        </p>
      </div>

      {patch && (patch.original_code || patch.patched_code) && (
        <div className="patch-code-section">
          <div className="section-heading">
            <div>
              <h2>Code Comparison</h2>
              <p>Original implementation versus the patch applied by the backend.</p>
            </div>
          </div>

          <div className="patch-comparison">
            <div className="patch-code-card">
              <div className="patch-code-header vulnerable-header">
                <div>
                  <AlertTriangle size={15} />
                  <strong>Original Code</strong>
                </div>
                <span>VULNERABLE</span>
              </div>
              <pre><code>{patch.original_code}</code></pre>
            </div>

            <div className="patch-code-card">
              <div className="patch-code-header secure-header">
                <div>
                  <ShieldCheck size={15} />
                  <strong>Applied Fix ({patch.method})</strong>
                </div>
                <span>SECURE</span>
              </div>
              <pre><code>{patch.patched_code}</code></pre>
            </div>
          </div>
        </div>
      )}

      {changes.length > 0 && (
        <div className="patch-changes">
          <h3>What changed?</h3>
          {changes.flatMap((c, ci) => [
            ...c.removed.map((line, i) => (
              <div className="patch-change" key={`r-${ci}-${i}`}>
                <span className="change-minus"><Minus size={13} /></span>
                <code>{line}</code>
              </div>
            )),
            ...c.added.map((line, i) => (
              <div className="patch-change" key={`a-${ci}-${i}`}>
                <span className="change-plus"><Plus size={13} /></span>
                <code>{line}</code>
              </div>
            )),
          ])}
        </div>
      )}

      {finding.remediation && (
        <div className="patch-changes">
          <h3>Pipeline steps</h3>
          {finding.remediation.steps.map((s) => (
            <div className="patch-change" key={s.step}>
              <span className="change-plus"><CheckCircle2 size={13} /></span>
              <code>{s.name}: {s.status}{s.detail ? ` — ${s.detail}` : ""}</code>
            </div>
          ))}
        </div>
      )}

      {patch?.status === "FAILED" && (
        <div className="verification-message failure-message">
          <AlertTriangle size={15} />
          Patch failed: {patch.reason}{patch.detail ? ` — ${patch.detail}` : ""}
        </div>
      )}

      <div className="patch-action">
        <div>
          <h3>Remediation</h3>
          <p>
            {applied
              ? `Patch applied to ${patch?.file}. Final status: ${finding.remediation?.final_status}.`
              : "Run the real Person 2 pipeline: reproduce the attack, patch, replay, regression."}
            {finding.remediationMs !== undefined && (
              <> {" "}<strong>Completed in {(finding.remediationMs / 1000).toFixed(1)}s.</strong></>
            )}
          </p>
        </div>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          {patch?.diff && (
            <button className="demo-nav-back" onClick={() => downloadDiff(finding)}>
              <Download size={15} />
              Download .diff
            </button>
          )}
          <button
            className={`apply-patch-button ${applied ? "applied-button" : ""}`}
            onClick={() => onRemediate(finding.id)}
            disabled={finding.busy || applied}
          >
            {finding.busy ? (
              <><Loader2 size={16} /> Remediating...</>
            ) : applied ? (
              <><CheckCircle2 size={16} /> {finding.verified ? "Patch Verified" : "Applied"}</>
            ) : (
              <><PlayCircle size={16} /> Remediate</>
            )}
          </button>
        </div>
      </div>

    </div>
  );
}

function Patches() {
  const { findings, remediate, remediateAll, loading, backendUp, error, busyIds } =
    useSecurity();

  const total = findings.length;
  const applied = findings.filter((f) => f.patchApplied).length;
  const verified = findings.filter((f) => f.verified).length;
  const anyBusy = Object.keys(busyIds).length > 0;

  return (
    <div className="page-container">

      <div className="page-heading">
        <div>
          <p className="breadcrumb">WORKSPACE / PATCHES</p>
          <h1>Security Patches</h1>
          <p className="subtitle">
            Apply real patches through Person 2's remediation pipeline.
          </p>
        </div>

        <button
          className="scan-button"
          onClick={() => void remediateAll()}
          disabled={anyBusy || total === 0}
        >
          {anyBusy ? <Loader2 size={17} /> : <PlayCircle size={17} />}
          {anyBusy ? "Remediating..." : "Remediate All"}
        </button>
      </div>

      {backendUp === false && (
        <div className="backend-banner">
          <AlertTriangle size={17} />
          {error ?? "Backend unavailable. Please ensure the PATCHPROOF backend is running."}
        </div>
      )}

      <div className="patch-summary">
        <div className="stat-card">
          <span>Total Patches</span>
          <strong className="stat-value">{String(total).padStart(2, "0")}</strong>
          <small>Findings to remediate</small>
        </div>

        <div className="stat-card">
          <span>Applied</span>
          <strong className="stat-value success-text">
            {String(applied).padStart(2, "0")}
          </strong>
          <small>Patches written to disk</small>
        </div>

        <div className="stat-card">
          <span>Verified</span>
          <strong className="stat-value success-text">
            {String(verified).padStart(2, "0")}
          </strong>
          <small>PATCH_VERIFIED</small>
        </div>
      </div>

      <div className="section-heading">
        <div>
          <h2>Patch Details</h2>
          <p>Each finding is remediated by the real backend pipeline.</p>
        </div>
      </div>

      {loading ? (
        <div className="verification-message">
          <Loader2 size={16} /> Loading findings...
        </div>
      ) : (
        findings.map((finding) => (
          <PatchCard key={finding.id} finding={finding} onRemediate={remediate} />
        ))
      )}

      <footer>
        PATCHPROOF <span>·</span> Security Remediation Platform
        <span className="footer-right">Live patches · Backend /full-remediation</span>
      </footer>

    </div>
  );
}

export default Patches;
