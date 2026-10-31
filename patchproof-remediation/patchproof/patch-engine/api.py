"""
PATCHPROOF remediation API.

Run:  uvicorn api:app --app-dir patch-engine --port 8000

The target directory is fixed by configuration (PATCHPROOF_TARGET_DIR,
default ./vulnerable-app); requests can never choose which directory is patched.
"""
import json
import os
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

import ai_patch  # noqa: E402
from models import Finding  # noqa: E402
from patcher import PATCHERS, ROOT_DIR, get_target_dir, patch_vulnerability, restore_originals  # noqa: E402
from pipeline import full_remediation  # noqa: E402
from regression import run_regression_tests  # noqa: E402
from verifier import run_security_test  # noqa: E402

SAMPLES_DIR = ROOT_DIR / "sample-findings"

app = FastAPI(title="PATCHPROOF Remediation Engine", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("PATCHPROOF_CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Patching rewrites files on disk; run one remediation at a time.
_LOCK = threading.Lock()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "target_dir": str(get_target_dir()),
        "supported_types": sorted(PATCHERS),
        "ai_available": ai_patch.ai_available(),
    }


@app.get("/samples")
def samples():
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(SAMPLES_DIR.glob("*.json"))}


@app.post("/patch")
def patch(finding: Finding, apply: bool = False):
    """Generate a patch. Set ?apply=true to write it to disk (with backup)."""
    with _LOCK:
        return patch_vulnerability(finding, apply=apply)


@app.post("/verify")
def verify(finding: Finding):
    """Replay the finding's attack against the code currently on disk."""
    with _LOCK:
        return run_security_test(finding)


@app.post("/regression")
def regression():
    with _LOCK:
        return run_regression_tests()


@app.post("/full-remediation")
def remediate(finding: Finding):
    with _LOCK:
        return full_remediation(finding)


@app.post("/reset")
def reset():
    """Restore every patched file to its original (vulnerable) state for another demo run."""
    with _LOCK:
        try:
            return {"restored": restore_originals()}
        except OSError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
