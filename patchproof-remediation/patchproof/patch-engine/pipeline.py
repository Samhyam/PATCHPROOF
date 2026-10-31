"""
Full remediation pipeline:

    REPRODUCE -> PATCH -> SECURITY VERIFY -> REGRESSION -> FINAL STATUS

PATCH_VERIFIED is only reported when the replayed attack is denied AND every
regression test passes. Any failed patch is rolled back from its backup.
"""
import ai_patch
from models import (
    DISPLAY_NAMES, FAIL, INVALID_FINDING, NOT_REPRODUCED, PASS, PATCH_FAILED,
    PATCH_VERIFIED, REGRESSION_FAILURE, VERIFICATION_ERROR, as_finding, normalize_type,
)
from patcher import (
    PatchError, build_patch_result, get_target_dir, patch_vulnerability,
    read_source, resolve_target_file, rollback_patch,
)
from regression import run_regression_tests
from verifier import run_security_test


def _ai_fallback(finding, target_dir):
    """Rule failed: ask AI for a suggestion. Returns (patch_or_None, suggestion)."""
    try:
        path = resolve_target_file(target_dir, finding.file)
    except PatchError as exc:
        return None, {"available": False, "message": str(exc)}
    source = read_source(path)
    suggestion = ai_patch.suggest_patch(finding, source)
    candidate = suggestion.pop("patched_source", None)
    if not candidate or not ai_patch.ai_apply_enabled():
        return None, suggestion
    ok, reason = ai_patch.validate_candidate(source, candidate)
    if not ok:
        suggestion["rejected"] = reason
        return None, suggestion
    try:
        patch = build_patch_result(finding, path, target_dir, source, candidate, "AI_SUGGESTED", "AI")
    except PatchError as exc:
        suggestion["rejected"] = str(exc)
        return None, suggestion
    return patch, suggestion


def full_remediation(finding, target_dir=None, rollback_on_failure=True) -> dict:
    try:
        finding = as_finding(finding)
    except Exception as exc:
        return {"final_status": INVALID_FINDING, "error": str(exc)}

    target_dir = get_target_dir(target_dir)
    vuln_type = normalize_type(finding.type)
    title = DISPLAY_NAMES.get(vuln_type, finding.type)
    result = {
        "id": finding.id,
        "type": vuln_type,
        "severity": finding.severity.upper(),
        "file": finding.file,
        "display": {"title": title, "severity": finding.severity.upper(), "patch_available": False},
        "explanation": ai_patch.explain_finding(finding),
        "patch": None,
        "verification": {"security_test": None, "regression_tests": None},
        "steps": [],
        "final_status": None,
    }

    def step(name, status, detail=""):
        result["steps"].append({"step": len(result["steps"]) + 1, "name": name, "status": status, "detail": detail})

    def finish(final_status):
        result["final_status"] = final_status
        step("Final status", final_status)
        return result

    def rollback(patch):
        if rollback_on_failure and patch.get("backup"):
            rollback_patch(patch["file"], patch["backup"], target_dir)
            result["patch"]["status"] = "ROLLED_BACK"
            step("Rollback", "DONE", "patched file restored from backup")

    step("Finding received", "DONE", f"{title} ({finding.severity.upper()}) in {finding.file}")

    # 1. Reproduce: the original attack must work before we patch anything.
    before = run_security_test(finding, target_dir)
    step("Reproduce original attack", before["status"], before.get("message", ""))
    if before["status"] == PASS:
        result["verification"]["security_test"] = {**before, "before": PASS, "after": None}
        return finish(NOT_REPRODUCED)
    if before["status"] != FAIL:
        result["verification"]["security_test"] = {**before, "before": before["status"], "after": None}
        return finish(VERIFICATION_ERROR)

    # 2. Patch (rule-based first, optional AI fallback).
    patch = patch_vulnerability(finding, target_dir, apply=True)
    if patch["status"] != "PATCHED":
        ai_result, suggestion = _ai_fallback(finding, target_dir)
        result["ai_suggestion"] = suggestion
        if ai_result is None:
            result["patch"] = {"status": "FAILED", "reason": patch["reason"], "detail": patch.get("detail")}
            step("Generate patch", "FAILED", patch.get("detail", ""))
            return finish(PATCH_FAILED)
        patch = ai_result

    result["display"]["patch_available"] = True
    result["patch"] = {
        "status": "APPLIED",
        "file": patch["file"],
        "diff": patch["diff"],
        "method": patch["patch_method"],
        "source": patch["source"],
        "original_code": patch["original_code"],
        "patched_code": patch["patched_code"],
        "changes": patch["changes"],
        "backup": patch.get("backup"),
    }
    step("Apply patch", "DONE", f"{patch['patch_method']} applied to {patch['file']}")

    # 3. Security verification: replay the same attack against the patched code.
    after = run_security_test(finding, target_dir)
    result["verification"]["security_test"] = {**after, "before": before["status"], "after": after["status"]}
    step("Replay original attack", after["status"], after.get("message", ""))
    if after["status"] != PASS:
        rollback(patch)
        return finish(PATCH_FAILED)

    # 4. Regression: normal functionality must still work.
    regression = run_regression_tests(target_dir)
    result["verification"]["regression_tests"] = regression
    summary = ", ".join(f"{t['name']} {t['status']}" for t in regression["tests"])
    step("Regression tests", regression["status"], summary)
    if regression["status"] != PASS:
        rollback(patch)
        return finish(REGRESSION_FAILURE)

    result["patch_explanation"] = ai_patch.explain_patch(finding, patch)
    return finish(PATCH_VERIFIED)
