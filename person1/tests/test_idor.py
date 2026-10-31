"""IDOR: detect + unauthorized access + structured evidence + standard JSON."""
from scanner import idor
from scanner.models import Finding


def test_idor_detected_and_exploited(client_and_dir):
    client, app_dir = client_and_dir
    finding, log = idor.scan(client, app_dir)

    assert finding is not None, f"IDOR not confirmed; log={log}"
    assert any("CONFIRMED" in line for line in log)

    assert finding.type == "IDOR"
    assert finding.severity == "HIGH"
    assert finding.file == "app.py"               # bare filename, as Person 2 expects
    assert finding.line and finding.line > 0

    ev = finding.evidence
    # Structured fields Person 2's verifier actually replays:
    attacker = ev.get("attacker")
    assert isinstance(attacker, dict) and attacker.get("username") and attacker.get("password")
    assert ev.get("victim_id") is not None
    assert attacker["username"] != "" and ev.get("victim_id") != attacker.get("id")
    assert ev.endpoint == "/profile/{user_id}"
    assert ev.method == "GET"
    assert "private profile" in ev.result.lower()


def test_idor_finding_is_standard_json(client_and_dir):
    client, app_dir = client_and_dir
    finding, _ = idor.scan(client, app_dir)
    data = finding.model_dump(exclude_none=True)
    Finding.model_validate(data)
    assert data["evidence"]["victim_id"] is not None
    assert data["evidence"]["attacker"]["password"]
