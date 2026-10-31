from patcher import patch_vulnerability
from verifier import run_security_test


def test_sqli_attack_succeeds_before_patch(app_dir, sqli_finding):
    result = run_security_test(sqli_finding, target_dir=app_dir)
    assert result["status"] == "FAIL"
    assert result["payload"] == "1 OR 1=1"
    assert result["details"]["attack_records"] > result["details"]["baseline_records"]


def test_sqli_attack_blocked_after_patch(app_dir, sqli_finding):
    assert patch_vulnerability(sqli_finding, target_dir=app_dir)["status"] == "PATCHED"
    result = run_security_test(sqli_finding, target_dir=app_dir)
    assert result["status"] == "PASS"
    assert result["message"] == "SQL Injection blocked"
    assert result["details"]["attack_records"] == 0


def test_idor_attack_succeeds_before_patch(app_dir, idor_finding):
    result = run_security_test(idor_finding, target_dir=app_dir)
    assert result["status"] == "FAIL"
    assert result["details"]["attack_http_status"] == 200


def test_idor_attack_blocked_after_patch(app_dir, idor_finding):
    assert patch_vulnerability(idor_finding, target_dir=app_dir)["status"] == "PATCHED"
    result = run_security_test(idor_finding, target_dir=app_dir)
    assert result["status"] == "PASS"
    assert result["details"]["attack_http_status"] == 403


def test_verifier_is_not_fooled_by_cosmetic_change(app_dir, sqli_finding):
    """A 'patch' that changes the file but not the behaviour must still FAIL."""
    db = app_dir / "database.py"
    db.write_text(db.read_text() + "\n# patched, trust me\n")
    assert run_security_test(sqli_finding, target_dir=app_dir)["status"] == "FAIL"


def test_broken_app_reports_error_not_pass(app_dir, sqli_finding):
    (app_dir / "app.py").write_text("this is not python(\n")
    assert run_security_test(sqli_finding, target_dir=app_dir)["status"] == "ERROR"
