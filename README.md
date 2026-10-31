# PATCHPROOF

> **Don't just find vulnerabilities. Prove they're fixed.**

PATCHPROOF is a closed-loop security remediation platform that **finds a vulnerability, proves it is exploitable, patches it, replays the original attack, and runs regression tests before declaring the patch verified.**

The project is split into three independent components:

```text
┌──────────────────────────────┐
│ Person 1 — Scanner           │
│ Find + Prove                 │
│ AST analysis + live exploit  │
└──────────────┬───────────────┘
               │ findings
               ▼
┌──────────────────────────────┐
│ Person 2 — Remediation       │
│ Patch + Replay + Regression  │
│ PATCH VERIFIED               │
└──────────────┬───────────────┘
               │ results
               ▼
┌──────────────────────────────┐
│ Person 3 — Dashboard         │
│ React UI + live workflow     │
└──────────────────────────────┘
```

## Why PATCHPROOF?

A patch is not trustworthy just because someone says it is fixed.

PATCHPROOF closes the loop:

```text
FIND
  ↓
PROVE THE ATTACK
  ↓
PATCH
  ↓
REPLAY THE SAME ATTACK
  ↓
CONFIRM IT IS BLOCKED
  ↓
RUN REGRESSION TESTS
  ↓
PATCH VERIFIED
```

The key idea is simple:

> **The attack that found the bug is the same attack that proves it's gone.**

## What the current demo proves

The bundled vulnerable application contains intentionally vulnerable examples for:

- **SQL Injection**
- **IDOR / Broken Access Control**

Person 1 dynamically proves the vulnerabilities before emitting findings.

Person 2 then:

1. reproduces the attack,
2. applies a security-specific patch,
3. replays the attack,
4. runs regression tests,
5. rolls back when verification/regression fails,
6. returns `PATCH_VERIFIED` only when the complete chain succeeds.

The current automated test suite contains **40 tests**:

- 11 scanner tests
- 29 remediation/backend tests

## Project structure

```text
PATCHPROOF/
├── person1/                              # Person 1 — live security scanner
│   ├── scanner/
│   │   ├── api.py                        # Scanner HTTP API (:8100)
│   │   ├── scanner.py                    # Scan orchestrator
│   │   ├── sqli.py                       # SQL injection detection + proof
│   │   ├── idor.py                       # IDOR detection + proof
│   │   ├── appload.py                    # Isolated target loading
│   │   ├── config.py                     # Target discovery/configuration
│   │   ├── models.py                     # Finding contract
│   │   └── person2.py                    # Person 2 integration for tests
│   ├── tests/
│   ├── findings.json
│   ├── demo.py
│   └── requirements.txt
│
├── patchproof-remediation/
│   └── patchproof/                       # Person 2 — remediation backend
│       ├── patch-engine/
│       │   ├── api.py                    # FastAPI backend (:8000)
│       │   ├── pipeline.py               # End-to-end orchestration
│       │   ├── patcher.py                # Security patch rules
│       │   ├── verifier.py               # Attack replay
│       │   ├── regression.py             # Regression tests
│       │   ├── diff_generator.py         # Unified diffs
│       │   ├── models.py                 # Finding/status contracts
│       │   └── ai_patch.py               # Optional patch suggestions
│       ├── vulnerable-app/               # Intentionally vulnerable demo app
│       ├── sample-findings/
│       ├── tests/
│       ├── demo.py
│       └── requirements.txt
│
├── frontend/                             # Person 3 — React dashboard (:5173)
│   ├── src/
│   │   ├── api/                          # Typed backend/scanner clients
│   │   ├── context/                      # Security workflow state
│   │   └── pages/                        # Scan, findings, patches, etc.
│   ├── package.json
│   └── .env.example
│
├── run-all.ps1                           # Start all three services on Windows
├── SETUP.md                              # Detailed setup instructions
└── README.md
```

## Quick start

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm

### Install dependencies

From the repository root:

```powershell
cd patchproof-remediation\patchproof
py -3 -m pip install -r requirements.txt
cd ..\..

cd person1
py -3 -m pip install -r requirements.txt
cd ..

cd frontend
npm install
cd ..
```

### Run everything

On Windows PowerShell:

```powershell
.\run-all.ps1
```

This launches:

| Component | URL |
|---|---|
| Person 2 backend | http://localhost:8000 |
| Person 1 scanner | http://localhost:8100 |
| Person 3 dashboard | http://localhost:5173 |

Open:

**http://localhost:5173**

### Run manually

If you prefer three terminals:

**Person 2 — backend**

```powershell
cd patchproof-remediation\patchproof
py -3 -m uvicorn api:app --app-dir patch-engine --port 8000
```

**Person 1 — scanner**

```powershell
cd person1
$env:PATCHPROOF_PROJECT="..\patchproof-remediation\patchproof"
py -3 -m uvicorn scanner.api:app --port 8100
```

**Person 3 — frontend**

```powershell
cd frontend
npm run dev
```

## Demo flow

1. Open the dashboard.
2. **Reset Backend** to restore the intentionally vulnerable baseline.
3. Go to **Security Scan** → **Run Live Scan**.
4. Person 1 analyzes the real target source and dynamically proves the vulnerabilities.
5. Review the evidence for SQL injection and IDOR.
6. Click **Remediate All**.
7. Person 2 generates and applies the appropriate security patches.
8. Person 2 replays the original attacks against the patched application.
9. Regression tests verify normal functionality.
10. The dashboard reports **PATCH VERIFIED** only when the complete chain succeeds.
11. Use **Reset & Repeat** to restore the vulnerable state for another demo run.

## Service APIs

### Person 1 — Scanner (`:8100`)

```text
GET /health
GET /scan
```

`GET /scan` performs a real source-code scan, dynamically proves discovered vulnerabilities, and returns structured findings plus the scanner log.

### Person 2 — Remediation (`:8000`)

```text
GET  /health
GET  /samples
POST /verify
POST /full-remediation
POST /regression
POST /reset
```

The important endpoint is:

```text
POST /full-remediation
```

It performs:

```text
reproduce → patch → replay → regression → final_status
```

### Person 3 — Frontend (`:5173`)

The React dashboard calls the scanner and remediation APIs and renders:

- live scan status,
- vulnerability evidence,
- patch diffs,
- remediation pipeline steps,
- verification results,
- regression results,
- final `PATCH VERIFIED` status.

The frontend also has a fallback to the backend's `/samples` endpoint if the scanner service is unavailable. This keeps the dashboard usable, but the live scan is explicitly identified when the Person 1 scanner is running.

## Security design

PATCHPROOF is intentionally built around verification rather than trusting a generated patch.

### SQL Injection

The remediation engine uses a parameterized-query patch strategy.

The verifier replays the original SQL injection payload and compares the malicious request against a benign baseline.

### IDOR

The remediation engine adds an authorization/ownership check.

The verifier logs in as the attacker and attempts to access another user's resource. A successful HTTP 200 response means the vulnerability is still exploitable.

### Regression protection

The remediation pipeline runs normal application behavior checks such as:

- authentication,
- user lookup,
- search,
- own-profile access,
- legitimate authorization.

If the patch blocks the exploit but breaks legitimate behavior, the result is not considered verified.

### Safe demo environment

The included `vulnerable-app` is deliberately insecure and exists only for local demonstration/testing.

**Do not deploy the vulnerable demo application to the public internet or use this project to attack systems you do not own or have permission to test.**

## Testing

### Person 1

```powershell
cd person1
py -3 -m pytest -q
```

Expected:

```text
11 passed
```

### Person 2

```powershell
cd patchproof-remediation\patchproof
py -3 -m pytest -q
```

Expected:

```text
29 passed
```

### Frontend

```powershell
cd frontend
npm run build
npm run lint
```

The frontend is built with React, TypeScript and Vite.

## Technology stack

### Detection & remediation

- Python
- FastAPI
- Python `ast`
- SQLite
- FastAPI `TestClient`
- pytest

### Frontend

- React 19
- TypeScript
- Vite
- React Router
- Recharts
- Lucide React

### Engineering

- HTTP APIs
- Strict JSON finding contract
- CORS
- Automated testing
- One-command Windows launcher

## Team architecture

**Person 1 — Security Engineer**

> Find + prove vulnerabilities.

Produces standardized findings with evidence that can be consumed directly by Person 2.

**Person 2 — Remediation/Backend Engineer**

> Explain + patch + replay + regression.

Owns the remediation pipeline and the authoritative `PATCH_VERIFIED` result.

**Person 3 — Frontend Engineer**

> Orchestrate + visualize.

Provides the dashboard, live scan experience, evidence, patch view, verification chain and reports.

## Project status

The current demo has been tested end-to-end with:

```text
Live scan
   ↓
SQL Injection + IDOR discovered
   ↓
Exploit confirmed
   ↓
Remediation
   ↓
Original attack replayed
   ↓
Attack blocked
   ↓
Regression tests passed
   ↓
PATCH VERIFIED
```

---

## License

No license has been selected for this repository yet. Add a license before treating the project as open-source software.
