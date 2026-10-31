"""
Person 1 Scanner API.

Exposes the scanner over HTTP so the dashboard (Person 3) can trigger a REAL,
live source-code scan: Person 1 parses the target app's source (AST), discovers
the vulnerabilities, dynamically proves each one is exploitable, and returns the
findings. This makes the architecture literally true end to end:

    Person 3 dashboard  ->  Person 1 /scan (discover + prove)  ->  findings
                        ->  Person 2 /full-remediation (patch + verify)

Run:  py -3 -m uvicorn scanner.api:app --port 8100
"""
import contextlib
import io
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import config  # noqa: E402
from scanner.scanner import run_scan  # noqa: E402

app = FastAPI(title="PATCHPROOF Person 1 Scanner API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "target": str(config.find_scan_target())}


@app.get("/scan")
def scan():
    """Run a real live scan and return discovered, exploit-proven findings."""
    # run_scan prints a human-readable report; keep it out of the HTTP response
    # (it still runs the real exploit replays).
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        findings = run_scan()
    return {
        "target": str(config.find_scan_target()),
        "count": len(findings),
        "findings": [f.model_dump(exclude_none=True) for f in findings],
        "log": buffer.getvalue(),
    }
