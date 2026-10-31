# PATCHPROOF — Short Description

PATCHPROOF is a closed-loop security remediation platform that finds vulnerabilities,
proves they are exploitable, patches them, replays the original attack, and runs
regression tests before declaring the patch verified.

**Pipeline:** Find → Prove → Patch → Replay → Regression → PATCH VERIFIED

**Current demo:** SQL Injection and IDOR / Broken Access Control in an intentionally
vulnerable local application.

**Architecture:** Person 1 live scanner → Person 2 FastAPI remediation engine →
Person 3 React dashboard.
