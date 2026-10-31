"""
Locate the things Person 1 needs to scan and to integrate with Person 2.

Person 2 is the source of truth for the integration contract. Person 1 scans a
*copy* of a vulnerable-app directory and emits findings whose `file` is a bare
filename (e.g. `database.py`) — exactly what Person 2's resolve_target_file
expects. We prefer Person 2's own vulnerable-app as the scan target so the
findings line up perfectly; otherwise we fall back to the bundled copy.

Discovery order (all optional, nothing is required to run standalone):
  - env PATCHPROOF_PROJECT      -> Person 2 project root (holds patch-engine/)
  - env PATCHPROOF_TARGET_DIR   -> a vulnerable-app directory to scan
  - a few well-known sibling / Downloads locations
"""
import os
from pathlib import Path

PERSON1_ROOT = Path(__file__).resolve().parent.parent
BUNDLED_APP = PERSON1_ROOT / "vulnerable_app"


def _looks_like_person2(root: Path) -> bool:
    root = Path(root)
    return (root / "patch-engine" / "pipeline.py").is_file() and (root / "vulnerable-app").is_dir()


def find_person2_root():
    """Return Person 2's project root (containing patch-engine/ and
    vulnerable-app/), or None if it cannot be located."""
    env = os.environ.get("PATCHPROOF_PROJECT")
    if env and _looks_like_person2(Path(env)):
        return Path(env).resolve()

    candidates = []
    # Sibling of Person 1, and common unzip locations.
    home = Path.home()
    for base in (PERSON1_ROOT.parent, home / "Downloads", home / "Desktop", home):
        candidates += [
            base / "patchproof-remediation" / "patchproof",
            base / "patchproof-remediation",
            base / "patchproof",
        ]
    # Walk a few parents of Person 1 as well.
    parent = PERSON1_ROOT
    for _ in range(4):
        parent = parent.parent
        candidates.append(parent / "patchproof-remediation" / "patchproof")

    for c in candidates:
        try:
            if _looks_like_person2(c):
                return c.resolve()
        except OSError:
            continue
    return None


def find_scan_target():
    """Return the vulnerable-app directory Person 1 should scan.

    Prefers an explicit target, then Person 2's own vulnerable-app, then the
    bundled fallback. The returned directory is only ever *read* and copied;
    Person 1 never writes into it.
    """
    env = os.environ.get("PATCHPROOF_TARGET_DIR")
    if env and Path(env).is_dir():
        return Path(env).resolve()

    person2 = find_person2_root()
    if person2 and (person2 / "vulnerable-app").is_dir():
        return (person2 / "vulnerable-app").resolve()

    return BUNDLED_APP.resolve()
