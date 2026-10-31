"""Shared fixtures for Person 1's tests."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner import config, person2  # noqa: E402
from scanner.appload import app_client  # noqa: E402


@pytest.fixture(scope="session")
def scan_target():
    """The vulnerable-app directory Person 1 scans (Person 2's own if found)."""
    return config.find_scan_target()


@pytest.fixture
def client_and_dir(scan_target):
    """A live TestClient over an isolated copy of the scan target."""
    with app_client(scan_target) as (client, copy_dir):
        yield client, copy_dir


@pytest.fixture(scope="session")
def generated_findings(scan_target, tmp_path_factory):
    """Run the full scanner once and return the findings exactly as they are
    written to and re-read from findings.json (the real integration path)."""
    import json
    from scanner.scanner import run_scan, write_findings

    findings = run_scan(scan_target)
    path = tmp_path_factory.mktemp("out") / "findings.json"
    write_findings(findings, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["findings"]


@pytest.fixture(scope="session")
def engine():
    """Person 2's real engine, or skip the test if Person 2 is not present."""
    eng = person2.load()
    if eng is None:
        pytest.skip("Person 2 project not found (set PATCHPROOF_PROJECT to enable)")
    return eng
