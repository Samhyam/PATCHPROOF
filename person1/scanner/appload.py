"""
Load a vulnerable demo app in-process so Person 1 can actually exploit it.

We never scan the original directory. Instead we copy it to a throwaway temp
dir and load the app from there (FastAPI TestClient, in-process, no network, no
open port). This guarantees Person 1 never modifies Person 2's files, and the
demo.db the app seeds on import is created only in the temp copy.

The module-swap dance mirrors Person 2's own verifier.load_app so that loading
our target does not disturb any other `app`/`database` modules already imported
in the same process (important when tests import Person 2's engine too).
"""
import ast
import contextlib
import importlib
import shutil
import sys
import tempfile
import threading
import warnings
from pathlib import Path

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

_LOAD_LOCK = threading.RLock()

_IGNORE = shutil.ignore_patterns(
    "__pycache__", ".patchproof_backups", "demo.db", "*.patchproof-tmp"
)


def parse_seed_users(app_dir):
    """Discover demo accounts (username/password/id) by reading SEED_USERS out of
    the target's database.py. Lets the IDOR scanner log in with real credentials
    instead of guessing. Returns a list of dicts ordered as seeded."""
    db = Path(app_dir) / "database.py"
    if not db.is_file():
        return []
    try:
        tree = ast.parse(db.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "SEED_USERS" for t in node.targets
        ):
            try:
                rows = ast.literal_eval(node.value)
            except (ValueError, SyntaxError):
                return []
            users = []
            for row in rows:
                if isinstance(row, (list, tuple)) and len(row) >= 3:
                    users.append({"id": row[0], "username": row[1], "password": row[2]})
            return users
    return []


def copy_target(src_dir) -> Path:
    """Copy a vulnerable-app directory to a fresh temp dir and return the copy."""
    tmp = Path(tempfile.mkdtemp(prefix="p1_scan_"))
    dest = tmp / "vulnerable-app"
    shutil.copytree(src_dir, dest, ignore=_IGNORE)
    return dest


def _load_app(app_dir: Path, module_name="app", attribute="app"):
    app_dir = Path(app_dir).resolve()
    local_names = {p.stem for p in app_dir.glob("*.py")}
    with _LOAD_LOCK:
        saved = {name: sys.modules.pop(name) for name in local_names if name in sys.modules}
        old_flag = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(app_dir))
        importlib.invalidate_caches()
        try:
            module = importlib.import_module(module_name)
            return getattr(module, attribute)
        finally:
            sys.path.remove(str(app_dir))
            sys.dont_write_bytecode = old_flag
            for name in local_names:
                sys.modules.pop(name, None)
            sys.modules.update(saved)


@contextlib.contextmanager
def app_client(src_dir):
    """Yield (TestClient, copy_dir) for a fresh, isolated copy of src_dir."""
    copy_dir = copy_target(src_dir)
    try:
        app = _load_app(copy_dir)
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client, copy_dir
    finally:
        shutil.rmtree(copy_dir.parent, ignore_errors=True)
