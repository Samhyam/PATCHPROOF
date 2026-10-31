# PATCHPROOF

### Find it. Prove it. Patch it. Prove the patch.

PATCHPROOF is a closed-loop application security platform that detects vulnerabilities, proves that they are exploitable, applies a targeted remediation, replays the same attack to confirm it is blocked, and runs regression tests to make sure normal functionality still works.

## The closed loop

```text
Person 1 — Scanner
    ↓
Find + prove vulnerability
    ↓ findings
Person 2 — Remediation Engine
    ↓
Patch → replay attack → regression
    ↓
PATCH_VERIFIED
    ↓
Person 3 — Dashboard
```

## What the demo proves

The included deliberately vulnerable demo application contains SQL Injection and IDOR / Broken Access Control vulnerabilities. Person 1 discovers and proves them with live exploit replay. Person 2 applies the corresponding remediation, replays the original attack, and runs regression tests. The dashboard presents the complete chain.

### Supported vulnerability classes

- SQL Injection → parameterized query remediation
- IDOR / Broken Access Control → authorization check remediation

## Components

| Component | Role | Technology |
|---|---|---|
| `person1/` | Find + Prove | Python, AST/source analysis, exploit replay |
| `patchproof-remediation/` | Patch + Verify + Regression | Python, FastAPI, SQLite, pytest |
| `frontend/` | Live dashboard | React, TypeScript, Vite |

## Run locally

### Prerequisites

- Python 3.11+
- Node.js 18+

### Windows one-command launcher

From the repository root:

```powershell
.\run-all.bat
```

or:

```powershell
powershell -ExecutionPolicy Bypass -File .\run-all.ps1
```

Then open `http://localhost:5173`. For manual setup and the three-terminal option, see [`SETUP.md`](SETUP.md).

## Demo flow

1. **Run Live Scan** — Person 1 discovers and proves the vulnerabilities.
2. **Remediate All** — Person 2 generates the real code diff and applies the remediation.
3. **Verify** — the same attack is replayed against the patched application.
4. **Regression** — normal functionality is tested.
5. **PATCH_VERIFIED** — only shown when the attack is blocked and regression tests pass.
6. **Reset** — restore the intentionally vulnerable demo for another run.

## Testing

Person 1:

```powershell
cd person1
py -3 -m pytest -q
```

Person 2:

```powershell
cd patchproof-remediation\patchproof
py -3 -m pytest -q
```

The completed integration run verified 11 Person 1 tests and 29 Person 2 tests.

## Security note

The `vulnerable-app` is intentionally insecure and exists only for local demonstration and testing. **Do not deploy it to the public internet.**

No real credentials, API keys, or local `.env` files are included in this repository. Copy `frontend/.env.example` to `frontend/.env` for local configuration when needed.

## Project structure

```text
PATCHPROOF/
├── person1/
├── patchproof-remediation/
├── frontend/
├── run-all.bat
├── run-all.ps1
├── SETUP.md
└── PROJECT_DESCRIPTION.md
```

## Team architecture

**Person 1 — Find + Prove:** reads application source, discovers vulnerabilities, proves exploitability, and emits the finding contract.

**Person 2 — Explain + Patch + Verify + Regression:** consumes findings, applies safe remediation, replays the attack, runs regression tests, and determines whether the patch is genuinely verified.

**Person 3 — Dashboard:** provides the browser interface for live scanning, findings, remediation, verification, reports, and reset.

## License

No license is currently specified.
