"""SQL Injection: detect + exploit + evidence + standard JSON."""
from scanner import sqli
from scanner.models import Finding


def test_sqli_detected_and_exploited(client_and_dir):
    client, app_dir = client_and_dir
    finding, log = sqli.scan(client, app_dir)

    assert finding is not None, f"SQLi not confirmed; log={log}"
    assert any("CONFIRMED" in line for line in log)

    assert finding.type == "SQL_INJECTION"
    assert finding.severity == "HIGH"
    assert finding.file == "database.py"          # bare filename, as Person 2 expects
    assert finding.line and finding.line > 0

    ev = finding.evidence
    assert ev.payload == "1 OR 1=1"
    assert ev.endpoint == "/users/lookup"
    assert ev.method == "GET"
    assert ev.parameter == "id"
    assert "records returned" in ev.result.lower()


def test_sqli_finding_is_standard_json(client_and_dir):
    client, app_dir = client_and_dir
    finding, _ = sqli.scan(client, app_dir)
    data = finding.model_dump(exclude_none=True)
    Finding.model_validate(data)
    assert {"id", "type", "severity", "file", "line", "description",
            "vulnerable_code", "evidence"} <= set(data)
