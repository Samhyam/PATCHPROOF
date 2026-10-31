# PATCHPROOF

> **Don't just find vulnerabilities. Prove they're fixed.**

PATCHPROOF is a closed-loop application-security demo that connects **live vulnerability discovery**, **automated remediation**, **attack replay**, and **regression testing** into one verifiable pipeline.

Instead of stopping at *"this looks vulnerable"*, PATCHPROOF asks a stronger question:

**Can we reproduce the vulnerability, patch it, replay the same attack, and prove normal functionality still works?**

```text
┌────────────────────┐
│ Person 1 — SCAN    │
│ Find + prove       │
│ real vulnerabilities
└─────────┬──────────┘
          │ strict JSON findings contract
          ▼
┌────────────────────┐
│ Person 2 — PATCH   │
│ Explain + patch    │
│ replay + regression│
└─────────┬──────────┘
          │ verification result
          ▼
┌────────────────────┐
│ Person 3 — VERIFY  │
│ Live React         │
│ security dashboard │
└────────────────────┘
```

## Why PATCHPROOF?

Traditional scanners can produce a finding and leave the developer with a question:

> **"Is it actually exploitable, and did my fix really work?"**

PATCHPROOF closes that loop:

**FIND → PROVE → PATCH → REPLAY → REGRESSION → PATCH VERIFIED**

A patch is not considered successful merely because the source code changed.

The final status is `PATCH_VERIFIED` only when:

1. the original vulnerability is reproduced;
2. the remediation is applied;
3. the original attack is replayed against the patched application;
4. the attack is blocked; and
5. normal application behaviour still passes regression tests.

---

## Architecture

| Component | Responsibility | Local endpoint |
|---|---|---|
| **Person 1 — Security Scanner** | Source-code analysis + live exploit proof; emits findings | `http://localhost:8100` |
| **Person 2 — Remediation Backend** | Patch generation, attack replay, regression testing, final verification | `http://localhost:8000` |
| **Person 3 — Dashboard** | React UI for scan, findings, patches, evidence and verification | `http://localhost:5173` |

### Service flow

```text
                    ┌─────────────────────┐
                    │   Target vulnerable │
                    │        app          │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ PERSON 1 — SCANNER  │
                    │ Find + Prove        │
                    │                     │
                    │ SQL Injection       │
                    │ IDOR                │
                    └──────────┬──────────┘
                               │ findings.json
                               ▼
                    ┌─────────────────────┐
                    │ PERSON 2 — BACKEND  │
                    │                     │
                    │ PATCH               │
                    │    ↓                │
                    │ REPLAY ATTACK       │
                    │    ↓                │
                    │ REGRESSION          │
                    │    ↓                │
                    │ PATCH_VERIFIED      │
                    └──────────┬──────────┘
                               │ HTTP API
                               ▼
                    ┌─────────────────────┐
                    │ PERSON 3 — DASHBOARD│
                    │ React + TypeScript  │
                    └─────────────────────┘
```

The scanner and remediation engine communicate through a strict JSON finding contract. The frontend communicates with the remediation backend over HTTP.

---

## What the current demo proves

The bundled deliberately vulnerable application contains two vulnerability classes:

### 1. SQL Injection

The demo scanner proves SQL injection by replaying a tautology payload:

```text
1 OR 1=1
```

The vulnerable query returns multiple user records instead of the single requested record.

The remediation engine replaces unsafe string concatenation with a parameterized query, then replays the attack.

### 2. Broken Access Control / IDOR

The scanner logs in as one user and requests another user's profile:

```text
GET /profile/2
```

The vulnerable application incorrectly returns the victim's private profile.

The remediation engine adds an ownership check and replays the same request.

---

## Verification philosophy

PATCHPROOF deliberately treats these as different states:

```text
EXPLOITABLE
    │
    │ patch
    ▼
PATCHED
    │
    │ replay original attack
    ▼
ATTACK BLOCKED
    │
    │ regression tests
    ▼
PATCH VERIFIED
```

This matters because a patch can appear correct while:

- leaving the original exploit path open;
- breaking legitimate functionality;
- changing unrelated behaviour; or
- modifying the wrong source file.

PATCHPROOF therefore makes **verification part of remediation**, not an afterthought.

---

## Technology stack

### Security / backend

- Python
- FastAPI
- Python `ast`
- SQLite
- FastAPI `TestClient`
- Pytest

### Frontend

- React 19
- TypeScript
- Vite
- React Router
- Recharts
- Lucide React

### Engineering

- Strict JSON contract between scanner and remediation engine
- HTTP APIs
- CORS
- Automated tests
- Windows one-command launcher
- Deliberately isolated vulnerable demo application

---

## Repository structure

```text
PATCHPROOF/
├── person1/                         # Person 1 — Find + Prove
│   ├── scanner/
│   │   ├── api.py                  # Scanner API (:8100)
│   │   ├── scanner.py              # Scan orchestration
│   │   ├── sqli.py                 # SQL injection detection/proof
│   │   ├── idor.py                 # IDOR detection/proof
│   │   ├── appload.py              # Isolated target-app loading
│   │   ├── models.py               # Finding contract
│   │   └── config.py
│   ├── tests/
│   ├── vulnerable_app/
│   ├── findings.json
│   ├── demo.py
│   └── requirements.txt
│
├── patchproof-remediation/          # Person 2 — Patch + Verify
│   └── patchproof/
│       ├── patch-engine/
│       │   ├── api.py              # Remediation API (:8000)
│       │   ├── pipeline.py         # End-to-end orchestration
│       │   ├── patcher.py          # Safe patch rules
│       │   ├── verifier.py         # Attack replay
│       │   ├── regression.py       # Regression tests
│       │   ├── diff_generator.py
│       │   ├── models.py
│       │   └── ai_patch.py
│       ├── vulnerable-app/
│       ├── sample-findings/
│       └── tests/
│
├── frontend/                        # Person 3 — Dashboard
│   ├── src/
│   │   ├── api/
│   │   ├── pages/
│   │   ├── context/
│   │   └── ui/
│   ├── package.json
│   └── .env.example
│
├── run-all.bat                      # Windows one-click launcher
├── run-all.ps1                      # Windows PowerShell launcher
├── SETUP.md
└── README.md
```

---

## Quick start

### Prerequisites

- **Python 3.11+**
- **Node.js 18+**
- `pip`
- `npm`

### 1. Install Person 2

```powershell
cd patchproof-remediation\patchproof
python -m pip install -r requirements.txt
cd ..\..
```

### 2. Install Person 1

```powershell
cd person1
python -m pip install -r requirements.txt
cd ..
```

### 3. Install the dashboard

```powershell
cd frontend
npm install
cd ..
```

### 4. Start everything

On Windows:

```powershell
.\run-all.bat
```

or:

```powershell
powershell -ExecutionPolicy Bypass -File .\run-all.ps1
```

Then open:

**http://localhost:5173**

For manual startup and troubleshooting, see [`SETUP.md`](SETUP.md).

---

## Run the tests

### Person 1

```powershell
cd person1
python -m pytest -q
```

### Person 2

```powershell
cd patchproof-remediation\patchproof
python -m pytest -q
```

The repository includes automated tests for scanner behaviour, exploit evidence, contract compatibility, patching, verification, regression, and end-to-end remediation.

---

## API endpoints

### Person 1 — Scanner

```text
GET http://localhost:8100/scan
```

The live scanner discovers and proves vulnerabilities in the target application and returns structured findings.

### Person 2 — Remediation

```text
GET  /health
GET  /samples
POST /verify
POST /full-remediation
POST /regression
POST /reset
```

Interactive API documentation:

```text
http://localhost:8000/docs
```

---

## Security design

The remediation engine is intentionally conservative.

- Only approved Python files inside the configured vulnerable-app directory can be modified.
- Path traversal outside the target directory is rejected.
- Original files are backed up before patching.
- Patch rules refuse to guess when the expected code structure is not found.
- Security verification uses the application's real HTTP routing and dependencies through an in-process test client.
- The final `PATCH_VERIFIED` state requires both attack blocking and regression success.
- Optional AI patch suggestions are not trusted to decide whether a vulnerability is fixed.

The bundled vulnerable application is **intentionally insecure** and is for local demonstration/testing only. Do not deploy it to a public or production environment.

---

## Environment configuration

The dashboard uses:

```text
frontend/.env.example
```

Copy it to `.env` for local development if you need to override the defaults:

```text
VITE_API_BASE_URL=http://localhost:8000
VITE_SCANNER_URL=http://localhost:8100
```

`.env` is intentionally excluded from the repository. Commit `.env.example`, never local secrets or machine-specific configuration.

---

## Demo sequence

For a clean presentation:

```text
1. Reset Backend
       ↓
2. Run Live Scan
       ↓
3. Person 1 proves SQL Injection + IDOR
       ↓
4. Remediate All
       ↓
5. Review the generated diff
       ↓
6. Verification
       ↓
7. Same attacks are replayed
       ↓
8. Regression tests pass
       ↓
9. PATCH VERIFIED
```

**The key demo moment is not the patch.**

It is the proof that the **same attack that worked before the patch no longer works after the patch — without breaking normal functionality.**

---

## Team architecture

PATCHPROOF is intentionally divided into three clear responsibilities:

**Person 1 — Security Engineer**  
Finds and proves vulnerabilities and produces the standardized finding.

**Person 2 — Remediation / Backend Engineer**  
Consumes the finding, explains the vulnerability, applies a safe patch, replays the exploit, runs regression tests, and returns the verified result.

**Person 3 — Frontend Engineer**  
Turns the complete pipeline into a judge-friendly live dashboard.

Each component can be tested independently while the complete system demonstrates the end-to-end security loop.

---

## Disclaimer

PATCHPROOF is a security engineering demonstration built around a deliberately vulnerable local application.

Use only against applications and systems you own or are explicitly authorized to test.
