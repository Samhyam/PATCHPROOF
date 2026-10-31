import { useState, type ReactNode } from "react";

import {
  ShieldCheck,
  LayoutDashboard,
  Bug,
  SearchCheck,
  Code2,
  FileCheck,
  FileText,
  Settings,
  Bell,
  ChevronDown,
  Menu,
  RotateCcw,
  AlertTriangle,
  Loader2,
  ArrowRight,
  ArrowLeft,
} from "lucide-react";

import Scan from "./pages/Scan";
import Findings from "./pages/Findings";
import Evidence from "./pages/Evidence";
import Patches from "./pages/Patches";
import Verification from "./pages/Verification";
import Reports from "./pages/Reports";

import { SecurityProvider, useSecurity } from "./context/SecurityContext";
import { statusTone } from "./ui/status";

import "./App.css";

function MainApp() {
  const [activePage, setActivePage] = useState("Overview");
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const { reset, backendUp, loading } = useSecurity();

  const handleReset = async () => {
    const confirmed = window.confirm(
      "Reset the demo backend? This restores the vulnerable app to its original state and clears scan/remediation results."
    );
    if (confirmed) {
      await reset();
    }
  };

  const navigation = [
    { name: "Overview", icon: LayoutDashboard },
    { name: "Security Scan", icon: SearchCheck },
    { name: "Security Findings", icon: Bug },
    { name: "Evidence", icon: SearchCheck },
    { name: "Patches", icon: Code2 },
    { name: "Verification", icon: FileCheck },
    { name: "Reports", icon: FileText },
  ];

  return (
    <div className="app">

      {/* SIDEBAR */}
      <aside className={`sidebar ${sidebarOpen ? "" : "collapsed"}`}>
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={25} />
          </div>
          {sidebarOpen && <span>PATCHPROOF</span>}
        </div>

        <div className="workspace">
          {sidebarOpen && (
            <>
              <span className="workspace-label">WORKSPACE</span>
              <button className="project-selector">
                VulnerableShop
                <ChevronDown size={15} />
              </button>
            </>
          )}
        </div>

        <div className="nav-section">
          {sidebarOpen && <p className="nav-label">MENU</p>}

          {navigation.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.name}
                className={`nav-item ${activePage === item.name ? "active" : ""}`}
                onClick={() => setActivePage(item.name)}
                title={item.name}
              >
                <Icon size={19} />
                {sidebarOpen && <span>{item.name}</span>}
              </button>
            );
          })}
        </div>

        <div className="sidebar-bottom">
          <button className="nav-item" onClick={handleReset} title="Reset Backend">
            <RotateCcw size={19} />
            {sidebarOpen && <span>Reset Backend</span>}
          </button>

          <button className="nav-item">
            <Settings size={19} />
            {sidebarOpen && <span>Settings</span>}
          </button>

          <div className="profile">
            <div className="avatar">PP</div>
            {sidebarOpen && (
              <div>
                <strong>Project Team</strong>
                <small>Developer workspace</small>
              </div>
            )}
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT */}
      <main className="main">
        <header className="topbar">
          <button
            className="icon-button"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label="Toggle sidebar"
          >
            <Menu size={20} />
          </button>

          <div className="topbar-right">
            <span
              className="environment"
              style={
                backendUp === false
                  ? { color: "#F09BA4", background: "#472D39" }
                  : backendUp
                  ? { color: "#76D5A8", background: "#1E4039" }
                  : undefined
              }
            >
              {backendUp === false
                ? "BACKEND OFFLINE"
                : backendUp
                ? "BACKEND CONNECTED"
                : "CONNECTING…"}
            </span>

            <button
              className="icon-button"
              onClick={handleReset}
              title="Reset Backend"
              aria-label="Reset Backend"
            >
              <RotateCcw size={19} />
            </button>

            <button className="icon-button" aria-label="Notifications">
              <Bell size={19} />
            </button>

            <div className="user-avatar">PP</div>
          </div>
        </header>

        <section className="content">
          {activePage === "Security Scan" ? (
            <Scan />
          ) : activePage === "Security Findings" ? (
            <Findings />
          ) : activePage === "Evidence" ? (
            <Evidence />
          ) : activePage === "Patches" ? (
            <Patches />
          ) : activePage === "Verification" ? (
            <Verification />
          ) : activePage === "Reports" ? (
            <Reports />
          ) : activePage === "Settings" ? (
            <div className="page-container">
              <div className="page-heading">
                <div>
                  <p className="breadcrumb">WORKSPACE / SETTINGS</p>
                  <h1>Settings</h1>
                  <p className="subtitle">Manage your PATCHPROOF workspace.</p>
                </div>
              </div>

              <div className="stat-card">
                <h3>Backend Data Management</h3>
                <p>Restore the vulnerable app and clear scan/remediation results.</p>
                <button className="scan-button" onClick={handleReset}>
                  <RotateCcw size={17} />
                  Reset Backend
                </button>
              </div>
            </div>
          ) : (
            <>
              {backendUp === false && (
                <div className="backend-banner">
                  <AlertTriangle size={17} />
                  Backend unavailable. Please ensure the PATCHPROOF backend is running
                  (uvicorn api:app --app-dir patch-engine --port 8000).
                </div>
              )}

              <div className="page-heading">
                <div>
                  <p className="breadcrumb">WORKSPACE / OVERVIEW</p>
                  <h1>Overview</h1>
                  <p className="subtitle">
                    Live PATCHPROOF status: find, prove, patch and verify.
                  </p>
                </div>

                <button
                  className="scan-button"
                  onClick={() => setActivePage("Security Scan")}
                >
                  <SearchCheck size={18} />
                  Run Scan
                </button>
              </div>

              <div className="welcome-card">
                <div>
                  <span className="welcome-tag">
                    <ShieldCheck size={15} />
                    SECURITY WORKSPACE
                  </span>
                  <h2>Welcome to PATCHPROOF</h2>
                  <p>
                    Findings come from the Person 1 scanner; patches and
                    verification run through the Person 2 backend.
                  </p>
                </div>
                <div className="welcome-shield">
                  <ShieldCheck size={76} strokeWidth={1.2} />
                </div>
              </div>

              <div className="section-heading">
                <div>
                  <h2>Security Overview</h2>
                  <p>{loading ? "Loading live status…" : "Current project security summary"}</p>
                </div>
              </div>

              <DashboardStats />

              <div className="section-heading findings-heading">
                <div>
                  <h2>Recent Security Findings</h2>
                  <p>Latest vulnerabilities identified in your project</p>
                </div>
                <button
                  className="text-button"
                  onClick={() => setActivePage("Security Findings")}
                >
                  View all findings →
                </button>
              </div>

              <DashboardFindings />

              <div className="section-heading workflow-heading">
                <div>
                  <h2>Remediation Workflow</h2>
                  <p>Track your security improvement process</p>
                </div>
              </div>

              <DashboardWorkflow />

              <footer>
                PATCHPROOF <span>·</span> Security Remediation Platform
                <span className="footer-right">
                  Live data · Person 1 + Person 2
                </span>
              </footer>
            </>
          )}

          <DemoNav current={activePage} onGo={setActivePage} />
        </section>
      </main>
    </div>
  );
}

/* GUIDED "NEXT" FLOW (sidebar is unchanged; this is an extra guided path) */
const DEMO_ORDER = [
  "Overview",
  "Security Scan",
  "Security Findings",
  "Evidence",
  "Patches",
  "Verification",
  "Reports",
];

function DemoNav({
  current,
  onGo,
}: {
  current: string;
  onGo: (page: string) => void;
}) {
  const i = DEMO_ORDER.indexOf(current);
  if (i === -1) return null; // hide on non-demo pages (e.g. Settings)

  const prev = i > 0 ? DEMO_ORDER[i - 1] : null;
  const next = i < DEMO_ORDER.length - 1 ? DEMO_ORDER[i + 1] : null;

  const go = (page: string) => {
    onGo(page);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <div className="demo-nav">
      {prev ? (
        <button className="demo-nav-back" onClick={() => go(prev)}>
          <ArrowLeft size={16} />
          {prev}
        </button>
      ) : (
        <span />
      )}

      {next ? (
        <button className="scan-button demo-nav-next" onClick={() => go(next)}>
          Next: {next}
          <ArrowRight size={18} />
        </button>
      ) : (
        <button className="scan-button demo-nav-next" onClick={() => go("Overview")}>
          <RotateCcw size={16} />
          Restart walkthrough
        </button>
      )}
    </div>
  );
}

/* WELCOME / LANDING SCREEN (shown once before the dashboard) */
function Welcome({ onEnter }: { onEnter: () => void }) {
  return (
    <div className="welcome-screen">
      <div className="welcome-hero">
        <span className="welcome-badge">
          <ShieldCheck size={15} />
          SECURITY REMEDIATION PLATFORM
        </span>

        <div className="welcome-logo">
          <div className="brand-icon">
            <ShieldCheck size={36} />
          </div>
        </div>

        <h1 className="welcome-title">PATCHPROOF</h1>

        <p className="welcome-sub">
          Find vulnerabilities, prove they're exploitable, patch them, and verify
          the fix — automatically, end to end.
        </p>

        <div className="welcome-steps">
          <span>Find</span>
          <i />
          <span>Prove</span>
          <i />
          <span>Patch</span>
          <i />
          <span>Verify</span>
        </div>

        <button className="scan-button welcome-cta" onClick={onEnter}>
          Enter Dashboard
          <ArrowRight size={18} />
        </button>
      </div>
    </div>
  );
}

/* DASHBOARD STATISTICS */
function DashboardStats() {
  const { findings } = useSecurity();

  const total = findings.length;
  const exploited = findings.filter((f) => f.exploited).length;
  const applied = findings.filter((f) => f.patchApplied).length;
  const verified = findings.filter((f) => f.verified).length;

  return (
    <div className="stats-grid">
      <StatCard title="Total Findings" value={pad(total)} detail="Detected vulnerabilities" icon={<Bug />} color="blue" />
      <StatCard title="Exploit Confirmed" value={pad(exploited)} detail="Proven exploitable" icon={<SearchCheck />} color="red" />
      <StatCard title="Patches Applied" value={pad(applied)} detail="Written to disk" icon={<Code2 />} color="purple" />
      <StatCard title="Verified Fixes" value={pad(verified)} detail="PATCH_VERIFIED" icon={<ShieldCheck />} color="green" />
    </div>
  );
}

/* DASHBOARD FINDINGS */
function DashboardFindings() {
  const { findings, loading } = useSecurity();

  if (loading) {
    return (
      <div className="findings-table">
        <div className="verification-message">
          <Loader2 size={16} /> Loading findings…
        </div>
      </div>
    );
  }

  return (
    <div className="findings-table">
      <div className="table-header">
        <span>VULNERABILITY</span>
        <span>SEVERITY</span>
        <span>LOCATION</span>
        <span>STATUS</span>
      </div>

      {findings.map((finding) => (
        <div className="table-row" key={finding.id}>
          <div className="finding-name">
            <div className="finding-icon red-icon">
              <Bug size={17} />
            </div>
            <div>
              <strong>{finding.displayName}</strong>
              <small>{finding.description}</small>
            </div>
          </div>

          <span>
            <span className="severity high">{finding.severity}</span>
          </span>

          <span className="location">
            {finding.file} : {finding.line ?? "?"}
          </span>

          <span>
            <span className={`status ${statusTone(finding.uiStatus)}`}>
              {finding.uiStatus}
            </span>
          </span>
        </div>
      ))}

      {findings.length === 0 && (
        <div className="verification-message">
          <AlertTriangle size={15} /> No findings loaded.
        </div>
      )}
    </div>
  );
}

/* WORKFLOW (reflects real progress) */
function DashboardWorkflow() {
  const { findings, scanned } = useSecurity();
  const anyExploited = findings.some((f) => f.exploited);
  const anyApplied = findings.some((f) => f.patchApplied);
  const anyVerified = findings.some((f) => f.verified);

  const steps = [
    { name: "Scan", description: "Find vulnerabilities", done: scanned || findings.length > 0 },
    { name: "Prove", description: "Confirm exploitable", done: anyExploited },
    { name: "Patch", description: "Apply code fixes", done: anyApplied },
    { name: "Verify", description: "Run security tests", done: anyVerified },
  ];

  return (
    <div className="workflow-card">
      {steps.map((step, index) => (
        <div className="workflow-step" key={step.name}>
          <div className={`step-circle ${step.done ? "completed" : ""}`}>
            {String(index + 1).padStart(2, "0")}
          </div>
          <strong>{step.name}</strong>
          <small>{step.description}</small>
          {index !== steps.length - 1 && <div className="step-connector" />}
        </div>
      ))}
    </div>
  );
}

function StatCard({
  title,
  value,
  detail,
  icon,
  color,
}: {
  title: string;
  value: string;
  detail: string;
  icon: ReactNode;
  color: string;
}) {
  return (
    <div className="stat-card">
      <div className="stat-top">
        <span>{title}</span>
        <div className={`stat-icon ${color}`}>{icon}</div>
      </div>
      <strong className="stat-value">{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function pad(n: number) {
  return String(n).padStart(2, "0");
}

function Root() {
  const [entered, setEntered] = useState(false);
  if (!entered) return <Welcome onEnter={() => setEntered(true)} />;
  return <MainApp />;
}

function App() {
  return (
    <SecurityProvider>
      <Root />
    </SecurityProvider>
  );
}

export default App;
