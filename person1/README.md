# PATCHPROOF — Person 1: Security Scanner (Find + Prove)

Person 1 of the PATCHPROOF pipeline. It **finds** vulnerabilities in the demo
application, **proves** they are exploitable by actually attacking a live copy
of the app, and emits a `findings.json` that Person 2's remediation engine
consumes **directly** — validated against Person 2's *real* `Finding` model and
driven through Person 2's *real* `full_remediation` pipeline in the tests.

```
Person 1 (Find + Prove)            Person 2 (Explain + Patch + Verify + Regression)
  scan live app                      Finding.model_validate(...)
  exploit SQLi + IDOR   -- findings.json -->   full_remediation(...)
  write findings.json                PATCH -> replay attack -> BLOCKED -> regression -> PATCH_VERIFIED
```

Person 1 **never patches** and **never modifies Person 2**. It scans a
*throwaway copy* of the target app, so even the original vulnerable app it scans
is left untouched.

## Built against the actual Person 2 contract

This scanner was written after inspecting Person 2's real code
(`patch-engine/models.py`, `verifier.py`, `patcher.py`, `pipeline.py`, `api.py`,
`sample-findings/`). Concretely, Person 1 matches Person 2 on:

| Contract point | Person 2 expectation | Person 1 output |
|---|---|---|
| `Finding` model | `id, type, severity, file, line, description, vulnerable_code, evidence` (extra allowed) | same fields, canonical values |
| Canonical types | `SQL_INJECTION`, `IDOR` | emits exactly these |
| `file` path | bare filename resolved inside Person 2's `vulnerable-app` (`resolve_target_file`) | `database.py`, `app.py` (no directory prefix) |
| SQLi evidence | `payload, endpoint, method, parameter` (verifier replays these) | all four populated |
| IDOR evidence | **structured** `attacker{username,password}` + `victim_id`, plus `endpoint` | populated from the app's real seed accounts |
| Login contract | `POST /login` JSON `{username,password}` → `{token}` | evidence credentials work against it |

## What it detects (and proves)

| Type | Location (Person 2's app) | Proof |
|---|---|---|
| `SQL_INJECTION` | `database.py:45` — `get_user_by_id()` string-concatenates `id` into SQL | payload `1 OR 1=1` returns **3 rows** vs 1 → all users dumped |
| `IDOR` | `app.py:67` — `/profile/{user_id}` has no ownership check | login as **alice**, `GET /profile/2` returns **bob's** private profile, HTTP 200 |

A finding is only emitted when the exploit produces observable evidence — never
from static suspicion alone.

## Project structure

```
person1/
├── scanner/
│   ├── __init__.py
│   ├── scanner.py        # orchestrator + entry point
│   ├── sqli.py           # SQL injection find + prove
│   ├── idor.py           # IDOR find + prove
│   ├── appload.py        # loads a COPY of the target app in-process (TestClient)
│   ├── config.py         # locates Person 2 / the scan target
│   ├── person2.py        # bridge to Person 2's REAL engine (tests only)
│   └── models.py         # local replica of Person 2's contract (self-check)
├── vulnerable_app/       # bundled fallback app (mirrors Person 2's exactly)
│   ├── app.py
│   └── database.py
├── tests/
│   ├── conftest.py
│   ├── test_sqli.py
│   ├── test_idor.py
│   ├── test_compatibility.py   # validates against Person 2's REAL Finding model
│   └── test_integration.py     # drives Person 2's REAL full_remediation pipeline
├── scanner.py            # root entry point (python scanner.py)
├── demo.py               # full end-to-end demo
├── findings.json         # generated output
├── requirements.txt
└── README.md
```

## Which part is whose

- **Person 1 = Find + Prove.** Everything in this repo.
- **Person 2 = Explain + Patch + Verify + Regression.** The `patchproof-remediation`
  project. Person 1 does not implement or modify any of it.

## Installation

```bash
py -3 -m pip install -r requirements.txt
```

## How Person 1 finds Person 2 (file-path assumptions)

Person 1 runs standalone without Person 2. When Person 2 **is** available, Person
1 scans Person 2's own `vulnerable-app` so findings line up perfectly. Discovery
order:

1. `PATCHPROOF_PROJECT` — Person 2 project root (the folder containing
   `patch-engine/` and `vulnerable-app/`).
2. `PATCHPROOF_TARGET_DIR` — a specific `vulnerable-app` directory to scan.
3. Well-known locations (sibling of `person1`, `~/Downloads/patchproof-remediation/patchproof`, …).
4. Fallback: the bundled `vulnerable_app/` (byte-for-byte the same vulnerable
   lines as Person 2's, so its findings are still valid for Person 2).

Because `file` is a **bare filename**, Person 2's `resolve_target_file` maps it
into whichever `vulnerable-app` Person 2 is configured to patch — no path
rewriting needed.

## Run the scanner

```bash
py -3 scanner.py
```

Output:

```
PATCHPROOF SECURITY SCANNER
[i] scanning app: .../patchproof/vulnerable-app

[+] SQL Injection scan
    - baseline id=1 -> HTTP 200, 1 row(s)
    - payload id='1 OR 1=1' -> HTTP 200, 3 row(s)
    - SQL injection CONFIRMED exploitable
[+] SQL Injection found and proven

[+] IDOR scan
    - logged in as alice (id=1)
    - GET /profile/2 as alice -> HTTP 200
    - IDOR CONFIRMED exploitable
[+] IDOR found and proven

[+] findings.json generated -> .../person1/findings.json
[+] findings compatible with Person 2 (validated against its real Finding model)
[+] 2 finding(s) written
```

## Full end-to-end demo (scan → findings.json → Person 2 patch verified)

```bash
py -3 demo.py
```

This also runs Person 2's **real** remediation pipeline on a throwaway copy of
its `vulnerable-app` and prints `PATCH_VERIFIED` for each finding.

## Run the tests

```bash
py -3 -m pytest -q
```

- `test_sqli.py` / `test_idor.py` — detection + live exploit + evidence + standard JSON.
- `test_compatibility.py` — every generated finding validates against Person 2's
  **actual** `Finding` model, and each `file` resolves via Person 2's
  `resolve_target_file`.
- `test_integration.py` — **functional** proof: each finding is fed into Person
  2's **actual** `full_remediation` (against an isolated copy) and must reach
  `PATCH_VERIFIED` (attack reproduced → patched → attack blocked → regression PASS).

The compatibility/integration tests **skip cleanly** if Person 2 is not present;
set `PATCHPROOF_PROJECT` to enable them.

## Example findings

See `findings.json`. Both findings use bare filenames and canonical types, and
the IDOR finding carries the structured `attacker` / `victim_id` evidence the
verifier replays.

## Integration with Person 2 (no adapter, no changes)

```python
import json
from models import Finding          # Person 2's unchanged model
from pipeline import full_remediation

data = json.load(open("findings.json"))
for item in data["findings"]:
    finding = Finding.model_validate(item)   # validates as-is
    result = full_remediation(finding)       # -> final_status: PATCH_VERIFIED
```

Person 1 produces the schema Person 2 already expects; nothing in Person 2 is
renamed, adapted, or modified.
```
