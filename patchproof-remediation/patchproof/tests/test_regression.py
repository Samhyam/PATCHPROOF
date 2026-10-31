from patcher import patch_vulnerability
from regression import run_regression_tests

EXPECTED = {"Login", "Normal user lookup", "Search", "Profile access", "Legitimate authorization"}


def _assert_all_pass(result):
    assert {t["name"] for t in result["tests"]} == EXPECTED
    assert result["status"] == "PASS", result["tests"]
    assert result["passed"] == len(EXPECTED) and result["failed"] == 0


def test_regression_passes_on_original_app(app_dir):
    _assert_all_pass(run_regression_tests(app_dir))


def test_sqli_regression(app_dir, sqli_finding):
    assert patch_vulnerability(sqli_finding, target_dir=app_dir)["status"] == "PATCHED"
    _assert_all_pass(run_regression_tests(app_dir))


def test_idor_regression(app_dir, idor_finding):
    assert patch_vulnerability(idor_finding, target_dir=app_dir)["status"] == "PATCHED"
    _assert_all_pass(run_regression_tests(app_dir))


def test_regression_detects_broken_functionality(app_dir):
    """A 'fix' that just returns nothing would stop the attack -- regression must catch it."""
    db = app_dir / "database.py"
    db.write_text(db.read_text().replace(
        'query = "SELECT * FROM users WHERE id=" + user_id',
        'query = "SELECT * FROM users WHERE 1=0"',
    ))
    result = run_regression_tests(app_dir)
    assert result["status"] == "FAIL"
    lookup = next(t for t in result["tests"] if t["name"] == "Normal user lookup")
    assert lookup["status"] == "FAIL"
