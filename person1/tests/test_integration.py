"""
Functional integration — the real proof.

Person 1's generated findings are fed into Person 2's ACTUAL remediation
pipeline (run against a throwaway copy of Person 2's vulnerable-app, so the
repo copy is never touched). This proves end-to-end:

    FIND -> PROVE -> findings.json -> Person 2 -> PATCH -> REPLAY ATTACK
    -> BLOCKED -> REGRESSION -> PATCH_VERIFIED

Schema validation alone is not enough; this executes the engine.
"""
import shutil

import pytest


def _by_type(findings, vuln_type):
    for f in findings:
        if f["type"] == vuln_type:
            return f
    pytest.fail(f"no {vuln_type} finding generated")


def test_vulnerabilities_reproduce_before_patch(generated_findings, engine):
    """Person 2's verifier confirms each finding's attack really works first."""
    copy = engine_fresh_copy(engine)
    try:
        for finding in generated_findings:
            result = engine.run_security_test(finding, target_dir=copy)
            assert result["status"] == engine.FAIL, (
                f"{finding['type']} should reproduce as vulnerable, got {result}"
            )
    finally:
        shutil.rmtree(copy.parent, ignore_errors=True)


def test_sqli_full_remediation_verified(generated_findings, engine):
    finding = _by_type(generated_findings, "SQL_INJECTION")
    copy = engine_fresh_copy(engine)
    try:
        result = engine.full_remediation(finding, target_dir=copy)
        assert result["verification"]["security_test"]["before"] == "FAIL"
        assert result["verification"]["security_test"]["after"] == "PASS"
        assert result["verification"]["regression_tests"]["status"] == "PASS"
        assert result["final_status"] == engine.PATCH_VERIFIED
    finally:
        shutil.rmtree(copy.parent, ignore_errors=True)


def test_idor_full_remediation_verified(generated_findings, engine):
    finding = _by_type(generated_findings, "IDOR")
    copy = engine_fresh_copy(engine)
    try:
        result = engine.full_remediation(finding, target_dir=copy)
        assert result["verification"]["security_test"]["after"] == "PASS"
        assert result["verification"]["regression_tests"]["status"] == "PASS"
        assert result["final_status"] == engine.PATCH_VERIFIED
    finally:
        shutil.rmtree(copy.parent, ignore_errors=True)


def test_both_findings_remediated_in_sequence(generated_findings, engine):
    """Both of Person 1's findings patch-verify against one app copy."""
    copy = engine_fresh_copy(engine)
    try:
        for vuln_type in ("SQL_INJECTION", "IDOR"):
            finding = _by_type(generated_findings, vuln_type)
            result = engine.full_remediation(finding, target_dir=copy)
            assert result["final_status"] == engine.PATCH_VERIFIED, (
                f"{vuln_type}: {result['final_status']}"
            )
    finally:
        shutil.rmtree(copy.parent, ignore_errors=True)


# Helper kept at module level so every test uses the same isolated-copy logic.
def engine_fresh_copy(engine):
    from scanner import person2
    return person2.fresh_copy()
