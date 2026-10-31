# PATCHPROOF — Setup & Run (any machine)

A self-verifying security remediation platform:

```
Person 1 scanner  →  discovers + proves vulnerabilities (live source-code scan)
       │ findings
Person 2 backend  →  patches → replays the attack → regression → PATCH_VERIFIED
       │ HTTP
Person 3 frontend →  live dashboard
```

## What's in this bundle
```
PATCHPROOF/
├── person1/                      # Person 1 — scanner (+ scan API)
├── patchproof-remediation/
│   └── patchproof/               # Person 2 — remediation backend + vulnerable demo app
├── frontend/                     # Person 3 — React dashboard
├── run-all.ps1                   # starts all 3 services (Windows)
└── SETUP.md
```
`node_modules`, virtualenvs and caches were removed to keep this small — you
reinstall them in one step below.

## Prerequisites
- **Python 3.11+**  (check: `python --version`)
- **Node.js 18+**  (check: `node --version`, `npm --version`)

> On Windows the Python launcher may be `py` instead of `python`. If `python`
> isn't found, use `py -3` in the commands below.

## Install (one time)
From the `PATCHPROOF` folder:

```bash
# Person 2 backend
cd patchproof-remediation/patchproof
pip install -r requirements.txt
cd ../..

# Person 1 scanner
cd person1
pip install -r requirements.txt
cd ..

# Person 3 frontend
cd frontend
npm install
cd ..
```

## Run

### Option A — one click (Windows)
Double-click **`run-all.bat`** in the `PATCHPROOF` folder, or from a terminal:
```powershell
powershell -ExecutionPolicy Bypass -File .\run-all.ps1
```
It opens three windows (backend :8000, scanner :8100, frontend :5173).

> Running `./run-all.ps1` directly may fail with *"is not digitally signed"* —
> Windows blocks scripts that came from a downloaded zip. The `.bat` / `-ExecutionPolicy
> Bypass` form above avoids that for this run only, without changing system settings.

### Option B — three terminals
```bash
# Terminal 1 — Person 2 backend (http://localhost:8000)
cd patchproof-remediation/patchproof
python -m uvicorn api:app --app-dir patch-engine --port 8000
```
```bash
# Terminal 2 — Person 1 scanner API (http://localhost:8100)
cd person1
python -m uvicorn scanner.api:app --port 8100
```
```bash
# Terminal 3 — Person 3 frontend (http://localhost:5173)
cd frontend
npm run dev
```

Then open **http://localhost:5173**.

## Demo flow
1. **Enter Dashboard** (welcome screen).
2. **Security Scan → Run Live Scan** — the terminal streams Person 1 discovering
   and proving each vulnerability; all show **EXPLOITABLE**.
3. **Patches → Remediate All** — real diff + pipeline steps, "Completed in ~0.5s",
   **Download .diff**.
4. **Verification** — reproduce → patch → replay → regression → **PATCH_VERIFIED**.
5. **Reset Backend** (sidebar) restores the vulnerable app for another run.

See `frontend/DEMO_SCRIPT.md` for a full video run-sheet.

## Run the tests
```bash
cd patchproof-remediation/patchproof && python -m pytest -q   # Person 2 (29)
cd person1 && python -m pytest -q                              # Person 1 (11)
```

## Notes
- Config is URL-based (`frontend/.env`): `VITE_API_BASE_URL` (backend) and
  `VITE_SCANNER_URL` (scanner). Defaults are localhost:8000 / :8100.
- If the scanner (:8100) isn't running, the dashboard falls back to findings
  served by the backend, so the demo still works.
- The demo app is intentionally vulnerable — local use only.
