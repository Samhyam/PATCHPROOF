"""
Schema compatibility — validate Person 1's generated findings against Person
2's ACTUAL Finding model (not a look-alike). Fails if any finding does not
conform to the real contract.
"""
import pytest

REQUIRED = {"id", "type", "severity", "file", "line",
            "description", "vulnerable_code", "evidence"}


def test_generated_findings_validate_against_person2_model(generated_findings, engine):
    assert len(generated_findings) >= 2, "expected both SQLi and IDOR findings"

    seen = set()
    for item in generated_findings:
        assert REQUIRED <= set(item), f"missing required fields in {item}"
        # Loads under Person 2's REAL Finding model, no adapter.
        model = engine.Finding.model_validate(item)
        assert model.type in {"SQL_INJECTION", "IDOR"}
        seen.add(model.type)

    assert seen == {"SQL_INJECTION", "IDOR"}


def test_file_paths_are_bare_and_resolvable(generated_findings, engine):
    """`file` must be a bare filename that Person 2's resolver maps into its
    own vulnerable-app."""
    from patcher import resolve_target_file  # Person 2's real resolver

    for item in generated_findings:
        assert "/" not in item["file"] and "\\" not in item["file"]
        resolved = resolve_target_file(engine.vulnerable_app, item["file"])
        assert resolved.is_file()


def test_person2_model_rejects_malformed(engine):
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        engine.Finding.model_validate({"id": "X", "type": "SQL_INJECTION"})  # no 'file'
