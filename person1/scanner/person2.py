"""
Bridge to Person 2's ACTUAL remediation engine, used for the real
compatibility and functional-integration checks.

Nothing here modifies Person 2. We import its real modules (Finding, pipeline,
verifier) and, for functional tests, run them against a throwaway *copy* of
Person 2's vulnerable-app via the engine's own `target_dir` parameter — the same
isolation Person 2's own test suite uses.
"""
import shutil
import sys
import tempfile
from pathlib import Path

from . import config

_IGNORE = shutil.ignore_patterns(
    "__pycache__", ".patchproof_backups", "demo.db", "*.patchproof-tmp"
)


def available() -> bool:
    return config.find_person2_root() is not None


def load():
    """Import and return Person 2's engine modules.

    Returns an object with .Finding, .full_remediation, .run_security_test,
    .PATCH_VERIFIED, .FAIL, or None if Person 2 cannot be located/imported.
    """
    root = config.find_person2_root()
    if not root:
        return None
    engine = str(root / "patch-engine")
    if engine not in sys.path:
        sys.path.insert(0, engine)
    try:
        import models
        import pipeline
        import verifier
    except Exception:
        return None

    class _Engine:
        project_root = root
        vulnerable_app = root / "vulnerable-app"
        Finding = models.Finding
        PATCH_VERIFIED = models.PATCH_VERIFIED
        FAIL = models.FAIL
        full_remediation = staticmethod(pipeline.full_remediation)
        run_security_test = staticmethod(verifier.run_security_test)

    return _Engine()


def copy_vulnerable_app(dest_parent) -> Path:
    """Copy Person 2's vulnerable-app into dest_parent and return the copy path.
    Person 2's repo copy is never touched."""
    root = config.find_person2_root()
    if not root:
        raise RuntimeError("Person 2 project not found")
    dest = Path(dest_parent) / "vulnerable-app"
    shutil.copytree(root / "vulnerable-app", dest, ignore=_IGNORE)
    return dest


def fresh_copy() -> Path:
    """Copy Person 2's vulnerable-app into a new temp dir (caller cleans up)."""
    return copy_vulnerable_app(tempfile.mkdtemp(prefix="p1_integ_"))
