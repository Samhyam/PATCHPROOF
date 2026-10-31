import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  Play,
  RefreshCw,
  Terminal,
  AlertTriangle,
} from "lucide-react";

import { useSecurity } from "../context/SecurityContext";
import type { FindingView } from "../context/SecurityContext";
import { statusTone } from "../ui/status";

type ChainState = "done" | "fail" | "waiting";

function ChainStep({ state, label }: { state: ChainState; label: string }) {
  return (
    <div className={`verify-chain-step ${state}`}>
      {state === "done" ? (
        <CheckCircle2 size={16} />
      ) : state === "fail" ? (
        <XCircle size={16} />
      ) : (
        <Clock size={16} />
      )}
      <span>{label}</span>
    </div>
  );
}

function VerificationChain({ finding }: { finding: FindingView }) {
  const r = finding.remediation;
  const sec = r?.verification.security_test;
  const reg = r?.verification.regression_tests;

  // "Not reproduced" = the code is already patched, so the original attack
  // cannot be reproduced. That is a safe state, not a patch failure.
  if (r?.final_status === "NOT_REPRODUCED") {
    return (
      <div className="verification-message success-message">
        <CheckCircle2 size={15} />
        Already patched — the original attack could not be reproduced on the
        current code. Click "Reset Backend" to demo from the vulnerable baseline.
      </div>
    );
  }

  const reproduced: ChainState =
    sec?.before === "FAIL" ? "done" : r ? "fail" : "waiting";
  const patched: ChainState =
    finding.patchApplied ? "done" : r ? "fail" : "waiting";
  const blocked: ChainState =
    sec?.after === "PASS" ? "done" : r && finding.patchApplied ? "fail" : "waiting";
  const regression: ChainState =
    reg?.status === "PASS" ? "done" : reg ? "fail" : "waiting";
  const verified: ChainState =
    finding.verified ? "done" : r ? "fail" : "waiting";

  return (
    <div className="verify-chain">
      <ChainStep state={finding.exploited ? "done" : "waiting"} label="Original vulnerability detected" />
      <div className="verify-chain-connector" />
      <ChainStep state={reproduced} label={`Attack reproduced${sec?.payload ? ` (payload: ${sec.payload})` : ""}`} />
      <div className="verify-chain-connector" />
      <ChainStep state={patched} label={`Patch applied${r?.patch?.method ? ` (${r.patch.method})` : ""}`} />
      <div className="verify-chain-connector" />
      <ChainStep state={blocked} label="Same attack replayed → blocked" />
      <div className="verify-chain-connector" />
      <ChainStep
        state={regression}
        label={`Regression tests ${reg ? `${reg.passed} passed, ${reg.failed} failed` : "pending"}`}
      />
      <div className="verify-chain-connector" />
      <ChainStep
        state={verified}
        label={`${r?.final_status ?? "PATCH VERIFIED (pending)"}${
          finding.remediationMs ? ` · ${(finding.remediationMs / 1000).toFixed(1)}s` : ""
        }`}
      />
    </div>
  );
}

function Verification() {
  const { findings, remediateAll, busyIds, backendUp, error, scanned } =
    useSecurity();

  const anyBusy = Object.keys(busyIds).length > 0;
  const verified = findings.filter((f) => f.verified).length;
  const alreadyPatched = findings.filter(
    (f) => f.remediation?.final_status === "NOT_REPRODUCED"
  ).length;
  const failed = findings.filter(
    (f) =>
      f.remediation &&
      !f.verified &&
      f.remediation.final_status !== "NOT_REPRODUCED"
  ).length;
  const ran = findings.some((f) => f.remediation);

  return (
    <div className="page-container">

      <div className="page-heading">
        <div>
          <p className="breadcrumb">WORKSPACE / VERIFICATION</p>
          <h1>Security Verification</h1>
          <p className="subtitle">
            Every result comes from Person 2: reproduce → patch → replay → regression.
          </p>
        </div>

        <button className="scan-button" onClick={() => void remediateAll()} disabled={anyBusy}>
          {anyBusy ? <RefreshCw size={17} /> : <Play size={17} />}
          {anyBusy ? "Running..." : "Run Verification"}
        </button>
      </div>

      {backendUp === false && (
        <div className="backend-banner">
          <AlertTriangle size={17} />
          {error ?? "Backend unavailable. Please ensure the PATCHPROOF backend is running."}
        </div>
      )}

      {alreadyPatched > 0 && (
        <div className="backend-banner ok">
          <CheckCircle2 size={17} />
          {alreadyPatched} finding(s) are already patched, so the original attack
          can't be reproduced (status NOT_REPRODUCED — not a failure). Click
          "Reset Backend" to run from the vulnerable baseline.
        </div>
      )}

      <div className="section-heading">
        <div>
          <h2>Verification Overview</h2>
          <p>Live security test results from the remediation pipeline</p>
        </div>
      </div>

      <div className="verification-stats">
        <div className="stat-card">
          <div className="stat-top">
            <span>Total Tests</span>
            <Terminal size={18} />
          </div>
          <strong className="stat-value">
            {String(findings.length).padStart(2, "0")}
          </strong>
          <small>Findings under verification</small>
        </div>

        <div className="stat-card">
          <div className="stat-top">
            <span>Verified</span>
            <CheckCircle2 size={18} color="#71D4AC" />
          </div>
          <strong className="stat-value success-text">
            {String(verified).padStart(2, "0")}
          </strong>
          <small>PATCH_VERIFIED</small>
        </div>

        <div className="stat-card">
          <div className="stat-top">
            <span>Failed</span>
            <XCircle size={18} color="#F08B9A" />
          </div>
          <strong className="stat-value danger-text">
            {String(failed).padStart(2, "0")}
          </strong>
          <small>Did not verify</small>
        </div>
      </div>

      <div className="section-heading verification-heading">
        <div>
          <h2>Security Test Results</h2>
          <p>Full remediation chain per vulnerability</p>
        </div>
      </div>

      <div className="verification-list">
        {findings.map((finding) => (
          <div className="verification-card" key={finding.id}>
            <div className="verification-card-top">
              <div className="verification-icon">
                <ShieldCheck size={21} />
              </div>

              <div className="verification-details">
                <h3>{finding.displayName} Verification</h3>
                <p>{finding.description}</p>
                <small>{finding.id} · {finding.file} : {finding.line ?? "?"}</small>
              </div>

              <span className={`status ${statusTone(finding.uiStatus)}`}>
                {finding.uiStatus}
              </span>
            </div>

            {finding.remediation || finding.busy ? (
              <VerificationChain finding={finding} />
            ) : (
              <div className="verification-message">
                <Clock size={15} />
                Run verification to execute the real remediation pipeline.
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="verification-info">
        <div className="evidence-heading">
          <ShieldCheck size={19} />
          <h3>Why Verification Matters</h3>
        </div>
        <p>
          A patch is not "verified" because a button was clicked. Person 2 replays
          the exact original attack against the patched code and runs regression
          tests; only when the attack is blocked AND normal functionality still
          works is the result <strong>PATCH_VERIFIED</strong>.
        </p>
        {!ran && !scanned && (
          <small>Verification has not been run yet.</small>
        )}
      </div>

      <footer>
        PATCHPROOF <span>·</span> Security Remediation Platform
        <span className="footer-right">Live verification · Backend pipeline</span>
      </footer>

    </div>
  );
}

export default Verification;
