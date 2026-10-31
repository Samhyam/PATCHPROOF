import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "patch-engine"))


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    """Tests must be deterministic: never call a real AI API."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("PATCHPROOF_ALLOW_AI_PATCH", raising=False)


@pytest.fixture
def app_dir(tmp_path):
    """A fresh, vulnerable copy of the demo app for each test (the repo copy is never touched)."""
    target = tmp_path / "vulnerable-app"
    shutil.copytree(
        ROOT / "vulnerable-app",
        target,
        ignore=shutil.ignore_patterns("__pycache__", ".patchproof_backups", "demo.db", "*.patchproof-tmp"),
    )
    return target


def _load(name):
    return json.loads((ROOT / "sample-findings" / name).read_text(encoding="utf-8"))


@pytest.fixture
def sqli_finding():
    return _load("sql_injection.json")


@pytest.fixture
def idor_finding():
    return _load("idor.json")
