# PATCHPROOF — Person 3 Frontend (live dashboard)

React + TypeScript + Vite dashboard for PATCHPROOF. It is a **real client** of
Person 2's FastAPI backend — no mock data, no `setTimeout` scans, no hard-coded
findings. Findings come from the Person 1 scanner (served by Person 2); patches
and verification run through Person 2's real remediation pipeline.

```
React Frontend (Person 3)
      │ HTTP (VITE_API_BASE_URL)
      ▼
Person 2 FastAPI backend  ──►  remediation engine  ──►  Person 1 findings
      │
      ▼  reproduce → patch → replay → regression
   PATCH_VERIFIED
```

## Which part is whose

- **Person 1 — Find + Prove.** Scanner + `findings.json`. Not modified.
- **Person 2 — Explain + Patch + Verify + Regression.** FastAPI backend. Not modified.
- **Person 3 — this frontend.** Displays live data and drives the backend.

## Backend endpoints used (from `patch-engine/api.py`)

| UI action | Endpoint | Notes |
|---|---|---|
| Load findings | `GET /samples` | the findings Person 1 produced, served by Person 2 |
| Backend status | `GET /health` | target dir, supported types |
| Scan (prove exploit) | `POST /verify` (body: Finding) | live attack replay; `FAIL` = exploitable |
| Remediate | `POST /full-remediation` (body: Finding) | reproduce → patch → replay → regression → `final_status` |
| Reset demo | `POST /reset` | restores the vulnerable app on disk |

No backend route was invented; there is no scan endpoint, so "scan" uses the real
`/verify` replay. **CORS** is already open (`allow_origins="*"`) in `api.py`, so
no Person 2 change is needed for the browser to call it.

## Data flow

```
Frontend → GET /samples        → Person 1 findings
Frontend → POST /verify        → Person 2 verifier replays the real attack  (FAIL = exploitable)
Frontend → POST /full-remediation → Person 2 patches, replays, runs regression → PATCH_VERIFIED
Frontend renders final_status, diff, pipeline steps and the verification chain
```

## Configuration

A single configurable base URL (`.env`):

```
VITE_API_BASE_URL=http://localhost:8000
```

All HTTP goes through `src/api/client.ts`; endpoint wrappers live in
`src/api/remediation.ts`; types mirror the backend in `src/api/types.ts`.

## Run everything (Windows)

Node.js is required (install once, e.g. `winget install OpenJS.NodeJS.LTS`, then
open a new terminal so `node`/`npm` are on PATH).

1. **Person 1 (optional — regenerate findings):** working dir `…/person1`
   ```bash
   py -3 scanner.py
   ```

2. **Person 2 backend:** working dir `…/patchproof-remediation/patchproof`, port 8000
   ```bash
   py -3 -m uvicorn api:app --app-dir patch-engine --port 8000
   ```

3. **Person 3 frontend:** working dir `…/PATCHPROOF/PATCHPROOF/frontend`, port 5173
   ```bash
   npm install
   ```
   ```bash
   npm run dev
   ```
   Then open http://localhost:5173.

Build / type-check:
```bash
npm run build
```

## Using the dashboard

```
Security Scan   → Run Live Scan      (both findings: EXPLOITABLE)
Security Findings / Evidence → live finding data + evidence
Patches         → Remediate All      (real diff + pipeline steps)
Verification    → full chain → PATCH_VERIFIED
Reports / Overview → live counts
Reset Backend   → restores the vulnerable app for another run
```

## Files added / changed

Added: `.env`, `.env.example`, `src/api/client.ts`, `src/api/types.ts`,
`src/api/remediation.ts`, `src/ui/status.ts`, `src/vite-env.d.ts`.
Changed: `src/context/SecurityContext.tsx` (backend-driven, no mock/localStorage),
`src/App.tsx`, `src/pages/{Scan,Findings,Evidence,Patches,Verification,Reports}.tsx`,
`src/App.css` (status tones + banner + chain). The visual design is preserved.

## Verified end-to-end (2026-10-31)

Backend started, frontend built (`tsc -b` clean) and served, browser connected:

- `GET /samples` → VULN-001 SQL_INJECTION (database.py:45), VULN-002 IDOR (app.py:67)
- Scan → both **EXPLOITABLE** (SQLi 3 vs 1 records; IDOR HTTP 200)
- Remediate → SQL_INJECTION **PATCH_VERIFIED**, IDOR **PATCH_VERIFIED**
  (before=FAIL, after=PASS, regression 5 passed / 0 failed)
- Overview/Reports show Total 2 · Exploit Confirmed 2 · Applied 2 · Verified 2
- No console errors. Person 1 (11 passed) and Person 2 (29 passed) unchanged.
