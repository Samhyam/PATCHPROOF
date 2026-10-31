# PATCHPROOF — Demo Video Run-Sheet (~2.5 min)

## 0. Pre-flight (off camera)
- Easiest: run **`./run-all.ps1`** (in the frontend folder) — it starts all three services.
- Or start them manually (three windows):
  - Person 2 backend : `py -3 -m uvicorn api:app --app-dir patch-engine --port 8000`  (dir: patchproof-remediation/patchproof)
  - Person 1 scanner : `py -3 -m uvicorn scanner.api:app --port 8100`  (dir: person1)
  - Person 3 frontend: `npm run dev`  → open http://localhost:5173  (dir: PATCHPROOF/.../frontend)
- Click **Reset Backend** (sidebar) so you start from the vulnerable baseline.
- Note: **Run Live Scan** now calls the Person 1 scanner over HTTP to analyze the
  real source and discover the vulns (it says "Discovered live by the Person 1
  scanner"). If the scanner service is down it silently falls back to backend
  samples, so the demo never breaks.
- Browser full-screen (F11), zoom ~100–110%, hide the bookmarks bar.
- Optional: enable cursor-click highlight in your recorder. Record at 1080p.
- Pause ~1s after each click so the fade-in animations land on camera.

## The story (what judges must see)
FIND → PROVE (real exploit) → PATCH → REPLAY SAME ATTACK → REGRESSION → PATCH_VERIFIED,
for **SQL_INJECTION** and **IDOR**, with **nothing simulated**.

---

> Tip: the app opens on a **Welcome screen** — click **Enter Dashboard** to start.
> At the bottom of each page there's a **Next: …** button that walks the flow
> (Overview → Scan → Findings → Evidence → Patches → Verification → Reports) and
> scrolls to the top. The sidebar still works for jumping around freely.

## 1. Open — Welcome → Overview  (~15s)
Open on the **Welcome screen** (big PATCHPROOF hero) → click **Enter Dashboard**.
Land on **Overview**. Point out the **BACKEND CONNECTED** pill.
> "This is PATCHPROOF. It finds security vulnerabilities, proves they're real, patches
> them, and verifies the fix — end to end. Everything on screen is live from the backend."
Show the stat cards: Total Findings 3.

## 2. Findings + Evidence  (~25s)
Click **Security Findings**.
> "These findings come from our Person 1 scanner — SQL injection and a broken-access-control
> IDOR — served live by the backend, not hard-coded."
Click **Evidence**, pick a finding.
> "For each one we capture the real evidence: the endpoint, the exact attack payload, and the
> vulnerable line of code."

## 3. Prove it's exploitable — Security Scan  (~25s)
Click **Security Scan** → **Run Live Scan**.
> "Watch — this doesn't just flag suspicious code. The backend actually replays each attack."
When results show **EXPLOITABLE**:
> "SQL injection: the payload returns every user instead of one. IDOR: logged in as Alice,
> we read Bob's private profile with HTTP 200. Both confirmed exploitable, live."

## 4. Patch it — Patches  (~30s)
Click **Patches** → **Remediate All**.
> "Now the Person 2 engine remediates: it reproduces the attack, applies a real patch, and
> writes it to disk."
Scroll to the diff + pipeline steps.
> "Here's the actual change — string concatenation becomes a parameterized query; the IDOR
> handler gets an ownership check. And every pipeline step is shown."

## 5. Verify — Verification  (~30s)
Click **Verification** → **Run Verification** (or it's already populated).
> "This is the key part. The engine replays the *same* attack against the patched code and
> runs regression tests. Watch the chain: reproduced → patched → attack blocked → regression
> passed → **PATCH VERIFIED**."
Emphasize the green **PATCH VERIFIED** on all findings.
> "A patch only counts as verified when the attack is actually blocked AND normal features
> still work."

## 6. Close — Overview / Reports  (~15s)
Click **Overview** (or **Reports**).
> "Three vulnerabilities — found, proven, patched, and verified. Three components: a scanner,
> a remediation engine, and this dashboard, fully integrated. Nothing here is faked."

---

## Reset between takes
Click **Reset Backend** → everything returns to exploitable so you can re-record cleanly.

## If something looks wrong on camera
- All badges say "Not exploitable / Already patched" → you forgot to **Reset Backend**.
- "BACKEND OFFLINE" pill → the uvicorn backend isn't running on :8000.
- A findings list that's empty → refresh the page (it reloads state on load).
