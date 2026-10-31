# PATCHPROOF: Remediation Engine (Person 2)

```
VULNERABILITY FOUND → PROVE → PATCH → VERIFY PATCH → REGRESSION TEST → PATCH VERIFIED
                              └──────────── this module ────────────┘
```

This module takes a vulnerability finding from the scanner (Person 1), patches the code,
**re-runs the original attack against the patched app**, runs normal functionality tests,
and returns one JSON result for the dashboard (Person 3).

A vulnerability is only ever reported `PATCH_VERIFIED` when the replayed attack is denied
**and** every regression test passes. Generating a patch is never enough.

## Architecture

```
finding JSON ─► pipeline.full_remediation()
                 │
                 ├─ 1. verifier.run_security_test()   replay attack  → must FAIL (vuln is real)
                 ├─ 2. patcher.patch_vulnerability()  rule-based fix + backup + diff
                 │        └─ no rule fits? ai_patch.suggest_patch()  (optional, untrusted)
                 ├─ 3. verifier.run_security_test()   replay attack  → must PASS (blocked)
                 ├─ 4. regression.run_regression_tests()             → must all PASS
                 └─ 5. final_status  (failed patches are rolled back from backup)
```

| File | Role |
|---|---|
| `patch-engine/patcher.py` | Rule registry (`PATCHERS`), SQLi + IDOR rules, path validation, backups, rollback, reset |
| `patch-engine/verifier.py` | Loads the app fresh from disk, replays the exploit through the real HTTP stack |
| `patch-engine/regression.py` | Login, user lookup, search, profile, legitimate-authorization checks |
| `patch-engine/diff_generator.py` | Unified diff + exact list of changed lines |
| `patch-engine/pipeline.py` | PATCH → VERIFY → REGRESSION → FINAL STATUS orchestration |
| `patch-engine/ai_patch.py` | Optional AI explanations / suggestions (never decides "fixed") |
| `patch-engine/models.py` | `Finding` model (scanner contract), type aliases, status constants |
| `patch-engine/api.py` | FastAPI service |
| `vulnerable-app/` | Deliberately vulnerable local demo app (SQLi + IDOR) |
| `demo.py` | One-command judge demo |

The verifier runs the app **in-process** with FastAPI's `TestClient`: real routing, real
dependencies, a real SQLite database, but no network. It can never hit an outside site.

## Install

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows   (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
```

## Run

```bash
python demo.py                  # full judge demo: SQLi then IDOR
python demo.py --reset          # restore the vulnerable app
pytest                          # 29 automated tests
uvicorn api:app --app-dir patch-engine --port 8000            # remediation API
uvicorn app:app --app-dir vulnerable-app --port 5000          # (optional) poke the demo app by hand
```

API docs: http://127.0.0.1:8000/docs

## Submitting a finding

Input contract (extra fields are allowed and kept):

```json
{
  "id": "VULN-001",
  "type": "SQL_INJECTION",
  "severity": "HIGH",
  "file": "database.py",
  "line": 45,
  "description": "User input is directly concatenated into SQL",
  "vulnerable_code": "query = \"SELECT * FROM users WHERE id=\" + user_id",
  "evidence": {
    "payload": "1 OR 1=1",
    "result": "Unexpected records returned",
    "endpoint": "/users/lookup",
    "method": "GET",
    "parameter": "id"
  }
}
```

`evidence.endpoint / method / parameter` tell the verifier how to replay the attack (defaults
match the demo app). IDOR findings also accept `evidence.attacker` (`username`, `password`)
and `evidence.victim_id`. See `sample-findings/`.

Accepted `type` aliases: `SQL_INJECTION`, `SQLI`, `CWE-89`, `IDOR`, `BROKEN_ACCESS_CONTROL`,
`CWE-639`, `INSECURE_DIRECT_OBJECT_REFERENCE`.

```bash
curl -X POST http://127.0.0.1:8000/full-remediation -H "Content-Type: application/json" -d @sample-findings/sql_injection.json
```

PowerShell:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/full-remediation -ContentType application/json -Body (Get-Content sample-findings\sql_injection.json -Raw)
```

## How patching works

**SQL injection → `PARAMETERIZED_QUERY`.** The rule finds the line matching `vulnerable_code`
(nearest to `line`), parses it with Python's `ast`, and splits the string concatenation /
f-string into SQL text and user-input expressions. It rewrites the SQL with `?` placeholders
(`%s` if the file uses psycopg/MySQL), then finds the `execute(query)` call in the same block
and passes the inputs as a parameter tuple. Quoted values (`name='" + name + "'`) and `LIKE`
wildcards are handled. Exactly two lines change.

**IDOR → `AUTHORIZATION_CHECK`.** The rule finds the route handler matching `evidence.endpoint`,
its object-id path parameter (`user_id`) and its authenticated-user dependency
(`current_user = Depends(get_current_user)`). It inserts an ownership check at the top of the
handler, using the same `current_user["id"]` / `current_user.id` style as the rest of the file,
and adds the `HTTPException` import if needed.

**The rule refuses (status `FAILED`) instead of guessing** when: the code isn't found, it is
already patched, the `execute()` call can't be found, the query variable is modified later,
quotes are unbalanced, the handler has no auth context, or the result doesn't compile.

**Safety:** only `.py` files inside `PATCHPROOF_TARGET_DIR` (default `vulnerable-app/`) can be
modified; `..` and outside paths are rejected; the API never lets a request choose the directory.
Before each write the file is copied to `.patchproof_backups/originals/` (first time) and
`.patchproof_backups/history/` (every time). Nothing in a finding is executed as a shell command.

**Adding a vulnerability type:** write `def patch_xss(source, finding) -> (patched_source, meta)`,
register it in `patcher.PATCHERS`, add a replay in `verifier.SECURITY_TESTS`, and an alias in
`models.TYPE_ALIASES`.

## How verification works

`verifier.run_security_test()` loads the app from disk fresh (clearing module caches and
`__pycache__`), and then:

- **SQL injection:** sends a benign request (`id=1`) and the payload (`id=1 OR 1=1`). If the
  payload returns more records than the benign request (or a 5xx), the attack succeeded →
  `FAIL`. Otherwise → `PASS`.
- **IDOR:** logs in as the attacker (alice), requests the victim's resource (`/profile/2`).
  HTTP 200 → `FAIL`. 401/403/404 → `PASS`. Anything else → `FAIL`. If login fails → `ERROR`.

The pipeline runs this **before** the patch (it must `FAIL`, or the result is `NOT_REPRODUCED`)
and **after** (it must `PASS`). Tests prove a cosmetic "patch" that changes text but not
behaviour still fails.

## How regression testing works

`regression.run_regression_tests()` runs real requests against the patched app:

| Test | Checks |
|---|---|
| Login | valid credentials get a token; a wrong password gets 401 |
| Normal user lookup | `id=1` → exactly alice, `id=2` → exactly bob |
| Search | `q=ali` finds alice |
| Profile access | alice can open her own profile |
| Legitimate authorization | bob can open `/profile/2` and `/me`; anonymous gets 401 |

A test whose routes don't exist in the app is `SKIPPED`, not passed. Tests prove that an
over-restrictive patch (blocking everyone) is caught → `REGRESSION_FAILURE` + rollback.

## Final status rules

| Result | `final_status` |
|---|---|
| attack blocked + all regression PASS | `PATCH_VERIFIED` |
| attack still works after patch, or no safe patch | `PATCH_FAILED` (patch rolled back) |
| attack blocked but regression fails | `REGRESSION_FAILURE` (patch rolled back) |
| attack didn't work before patching | `NOT_REPRODUCED` (nothing patched) |
| test couldn't run (app broken, attacker login failed) | `VERIFICATION_ERROR` |

## Example SQL injection flow (`python demo.py`)

```
STEP 3  SQL Injection | HIGH | Patch Available
        Before patch, attack replay: ATTACK SUCCEEDED
STEP 4  Patch generated and applied (PARAMETERIZED_QUERY):
        -    query = "SELECT * FROM users WHERE id=" + user_id
        -    cursor.execute(query)
        +    query = "SELECT * FROM users WHERE id=?"
        +    cursor.execute(query, (user_id,))
STEP 5  Original payload replayed: 1 OR 1=1
        Result: ATTACK BLOCKED ✅
STEP 6  Login PASS · Normal user lookup PASS · Search PASS · Profile access PASS · Legitimate authorization PASS
STEP 7  FINAL STATUS: PATCH VERIFIED ✅
```

## Example IDOR flow

```
STEP 4  Patch generated and applied (AUTHORIZATION_CHECK):
         def get_profile(user_id: int, current_user: dict = Depends(get_current_user)):
        +    # PATCHPROOF: object-level authorization check (IDOR fix)
        +    if str(user_id) != str(current_user["id"]):
        +        raise HTTPException(status_code=403, detail="Forbidden: you can only access your own resources")
STEP 5  Original payload replayed: alice requests GET /profile/2 → ATTACK BLOCKED ✅ (HTTP 403)
STEP 7  FINAL STATUS: PATCH VERIFIED ✅
```

## API

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/health` | | target dir, supported types, AI availability |
| GET | `/samples` | | the sample findings |
| POST | `/patch?apply=false` | finding | patch result (dry run unless `apply=true`) |
| POST | `/verify` | finding | security test against the code currently on disk |
| POST | `/regression` | | regression results |
| POST | `/full-remediation` | finding | full unified result (below) |
| POST | `/reset` | | restores all patched files for another demo run |

`/patch` result:

```json
{
  "status": "PATCHED",
  "vulnerability_id": "VULN-001",
  "file": "database.py",
  "original_code": "query = \"SELECT * FROM users WHERE id=\" + user_id\ncursor.execute(query)",
  "patched_code": "query = \"SELECT * FROM users WHERE id=?\"\ncursor.execute(query, (user_id,))",
  "diff": "--- vulnerable/database.py\n+++ patched/database.py\n...",
  "patch_method": "PARAMETERIZED_QUERY",
  "source": "RULE_BASED",
  "changes": [{"action": "replace", "original_lines": [45, 46], "patched_lines": [45, 46], "removed": ["..."], "added": ["..."]}],
  "applied": false
}
```

or `{"status": "FAILED", "reason": "Unable to generate safe patch", "detail": "..."}`.

`/full-remediation` result (abridged):

```json
{
  "id": "VULN-001",
  "type": "SQL_INJECTION",
  "severity": "HIGH",
  "display": {"title": "SQL Injection", "severity": "HIGH", "patch_available": true},
  "explanation": {"source": "template", "text": "The application builds a database query by ..."},
  "patch": {"status": "APPLIED", "file": "database.py", "diff": "...", "method": "PARAMETERIZED_QUERY", "source": "RULE_BASED"},
  "verification": {
    "security_test": {"status": "PASS", "payload": "1 OR 1=1", "message": "SQL Injection blocked",
                      "before": "FAIL", "after": "PASS",
                      "details": {"baseline_records": 1, "attack_records": 0, "attack_http_status": 200}},
    "regression_tests": {"status": "PASS", "passed": 5, "failed": 0, "skipped": 0,
                         "tests": [{"name": "Login", "status": "PASS", "message": "..."}]}
  },
  "steps": [
    {"step": 1, "name": "Finding received", "status": "DONE"},
    {"step": 2, "name": "Reproduce original attack", "status": "FAIL"},
    {"step": 3, "name": "Apply patch", "status": "DONE"},
    {"step": 4, "name": "Replay original attack", "status": "PASS"},
    {"step": 5, "name": "Regression tests", "status": "PASS"},
    {"step": 6, "name": "Final status", "status": "PATCH_VERIFIED"}
  ],
  "final_status": "PATCH_VERIFIED"
}
```

## Optional AI layer

Set `ANTHROPIC_API_KEY` and `pip install anthropic` to get AI-written plain-English
explanations and, when no rule fits, a patch **suggestion** (model: `PATCHPROOF_AI_MODEL`,
default `claude-sonnet-5-5`). Without a key, everything runs on deterministic rules and templates.

AI code is never applied unless you also set `PATCHPROOF_ALLOW_AI_PATCH=1`. Even then it must
pass a static gate (parses, no new imports, no new `eval`/`exec`/`subprocess`/file calls), then
the same security test and regression suite as a rule-based patch. AI never sets `final_status`.

## Integration: Person 1 (scanner)

1. Emit findings in the JSON contract above. `file` can be relative to the app
   (`database.py`), prefixed (`vulnerable-app/database.py`), or absolute inside the app dir.
2. Include how to replay the attack in `evidence` (`endpoint`, `method`, `parameter`, `payload`;
   for IDOR also `attacker` and `victim_id`).
3. Send it: `POST /full-remediation`, or in Python:
   ```python
   import sys; sys.path.insert(0, "patch-engine")
   from pipeline import full_remediation
   result = full_remediation(finding_dict)
   ```
4. To point the engine at a different local app, set `PATCHPROOF_TARGET_DIR`. The app must be a
   FastAPI app exposed as `app` in `app.py`.

## Integration: Person 3 (dashboard)

- Call `POST /full-remediation` with the finding; CORS is open by default
  (`PATCHPROOF_CORS_ORIGINS` to restrict).
- Header card: `display.title`, `display.severity`, `display.patch_available`.
- Diff panel: `patch.diff` (unified diff; colour lines starting with `-` / `+`).
- Attack panel: `verification.security_test` (`payload`, `before`, `after`, `message`).
- Regression panel: `verification.regression_tests.tests[]`.
- Timeline: `steps[]`. Badge: `final_status`.
- "Run again" button: `POST /reset`.

## Demonstrating to judges (3 minutes)

1. `python demo.py --reset`, then show `vulnerable-app/database.py` line 45 (string-concatenated SQL).
2. Run `python demo.py`. Walk through the SQLi block: the attack works first (**proof**), then
   the 2-line diff, then the **same payload replayed** returns 0 records → ATTACK BLOCKED, then 5
   regression tests pass → **PATCH VERIFIED**.
3. Same for IDOR: alice reads bob's profile → patch adds the ownership check → alice gets 403,
   bob still reads his own → **PATCH VERIFIED**.
4. Prove the verdict is honest: `pytest -k "rejected or cosmetic or broken" -v`. A fake fix that
   only adds a comment is caught by the security test; a fix that blocks everyone is caught by
   regression and rolled back.
5. `python demo.py --reset` to restore.

> ⚠️ `vulnerable-app/` is intentionally insecure. Run it only on localhost, for this demo.
