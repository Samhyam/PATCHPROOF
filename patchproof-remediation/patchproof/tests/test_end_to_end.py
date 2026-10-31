import patcher
from fastapi.testclient import TestClient
from pipeline import full_remediation
from verifier import run_security_test


def test_full_remediation(app_dir, sqli_finding):
    """Vulnerability exists -> patch applied -> original attack fails -> app still works -> PATCH_VERIFIED."""
    # The vulnerability really exists before we start.
    assert run_security_test(sqli_finding, target_dir=app_dir)["status"] == "FAIL"

    result = full_remediation(sqli_finding, target_dir=app_dir)

    assert result["patch"]["status"] == "APPLIED"
    assert result["patch"]["method"] == "PARAMETERIZED_QUERY"
    security = result["verification"]["security_test"]
    assert security["before"] == "FAIL" and security["after"] == "PASS"
    assert security["payload"] == "1 OR 1=1"
    regression = result["verification"]["regression_tests"]
    assert regression["status"] == "PASS" and regression["failed"] == 0
    assert result["final_status"] == "PATCH_VERIFIED"
    assert [s["name"] for s in result["steps"]] == [
        "Finding received", "Reproduce original attack", "Apply patch",
        "Replay original attack", "Regression tests", "Final status",
    ]
    # The fix is really on disk.
    assert "WHERE id=?" in (app_dir / "database.py").read_text()


def test_full_remediation_idor(app_dir, idor_finding):
    result = full_remediation(idor_finding, target_dir=app_dir)
    assert result["verification"]["security_test"]["after"] == "PASS"
    assert result["verification"]["regression_tests"]["status"] == "PASS"
    assert result["final_status"] == "PATCH_VERIFIED"


def test_both_vulnerabilities_in_sequence(app_dir, sqli_finding, idor_finding):
    assert full_remediation(sqli_finding, target_dir=app_dir)["final_status"] == "PATCH_VERIFIED"
    assert full_remediation(idor_finding, target_dir=app_dir)["final_status"] == "PATCH_VERIFIED"


def test_already_fixed_is_not_reproduced(app_dir, sqli_finding):
    full_remediation(sqli_finding, target_dir=app_dir)
    again = full_remediation(sqli_finding, target_dir=app_dir)
    assert again["final_status"] == "NOT_REPRODUCED"
    assert again["patch"] is None


def test_over_restrictive_patch_is_rejected_and_rolled_back(app_dir, idor_finding, monkeypatch):
    """A patch that blocks EVERYONE stops the attack but breaks the app -> REGRESSION_FAILURE."""
    def deny_everyone(source, finding):
        anchor = "    profile = database.get_profile(user_id)\n"
        return source.replace(anchor, '    raise HTTPException(status_code=403, detail="nope")\n' + anchor), {}

    monkeypatch.setitem(patcher.PATCHERS, "IDOR", (deny_everyone, "AUTHORIZATION_CHECK"))
    original = (app_dir / "app.py").read_text()

    result = full_remediation(idor_finding, target_dir=app_dir)

    assert result["verification"]["security_test"]["after"] == "PASS"  # attack is blocked...
    assert result["verification"]["regression_tests"]["status"] == "FAIL"  # ...but so is everyone else
    assert result["final_status"] == "REGRESSION_FAILURE"
    assert result["patch"]["status"] == "ROLLED_BACK"
    assert (app_dir / "app.py").read_text() == original


def test_ineffective_patch_is_rejected(app_dir, sqli_finding, monkeypatch):
    """A patch that changes code but not behaviour -> PATCH_FAILED, never PATCH_VERIFIED."""
    monkeypatch.setitem(
        patcher.PATCHERS, "SQL_INJECTION",
        (lambda source, finding: (source + "\n# fixed!\n", {}), "PARAMETERIZED_QUERY"),
    )
    result = full_remediation(sqli_finding, target_dir=app_dir)
    assert result["verification"]["security_test"]["after"] == "FAIL"
    assert result["final_status"] == "PATCH_FAILED"


def test_unpatchable_finding_reports_failure(app_dir, sqli_finding):
    result = full_remediation({**sqli_finding, "vulnerable_code": "nothing like this", "line": None,
                               "file": "app.py"}, target_dir=app_dir)
    assert result["final_status"] == "PATCH_FAILED"
    assert result["patch"]["status"] == "FAILED"
    assert result["ai_suggestion"]["available"] is False


def test_api_full_remediation(app_dir, sqli_finding, monkeypatch):
    monkeypatch.setenv("PATCHPROOF_TARGET_DIR", str(app_dir))
    import api

    client = TestClient(api.app)
    assert client.get("/health").json()["target_dir"] == str(app_dir.resolve())
    assert client.post("/verify", json=sqli_finding).json()["status"] == "FAIL"
    assert client.post("/patch", json=sqli_finding).json()["status"] == "PATCHED"  # dry run
    response = client.post("/full-remediation", json=sqli_finding)
    assert response.status_code == 200
    assert response.json()["final_status"] == "PATCH_VERIFIED"
    assert client.post("/regression").json()["status"] == "PASS"
    assert client.post("/reset").json()["restored"] == ["database.py"]
    assert client.post("/verify", json=sqli_finding).json()["status"] == "FAIL"
