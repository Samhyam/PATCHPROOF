"""
Shared data models and constants for the PATCHPROOF remediation engine.

The Finding model mirrors the JSON contract with Person 1's scanner. Unknown
fields are kept (extra="allow") so the scanner can send more than we use.
"""
import re
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class Evidence(BaseModel):
    model_config = ConfigDict(extra="allow")

    payload: Optional[str] = None
    result: Optional[str] = None
    # Optional hints that tell the verifier how to replay the attack.
    endpoint: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None

    def get(self, key, default=None):
        value = getattr(self, key, None)
        if value is None:
            value = (self.model_extra or {}).get(key)
        return default if value is None else value


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    type: str
    severity: str = "MEDIUM"
    file: str
    line: Optional[int] = None
    description: str = ""
    vulnerable_code: str = ""
    evidence: Evidence = Field(default_factory=Evidence)


def as_finding(finding) -> Finding:
    return finding if isinstance(finding, Finding) else Finding.model_validate(finding)


# Canonical vulnerability types. Add new aliases here when Person 1's scanner
# uses a different name for a supported type.
SQL_INJECTION = "SQL_INJECTION"
IDOR = "IDOR"

TYPE_ALIASES = {
    "SQL_INJECTION": SQL_INJECTION,
    "SQLI": SQL_INJECTION,
    "CWE_89": SQL_INJECTION,
    "IDOR": IDOR,
    "BROKEN_ACCESS_CONTROL": IDOR,
    "IDOR_BROKEN_ACCESS_CONTROL": IDOR,
    "INSECURE_DIRECT_OBJECT_REFERENCE": IDOR,
    "CWE_639": IDOR,
}

DISPLAY_NAMES = {
    SQL_INJECTION: "SQL Injection",
    IDOR: "IDOR / Broken Access Control",
}


def normalize_type(vuln_type: str) -> str:
    key = re.sub(r"[\s\-/]+", "_", (vuln_type or "").strip().upper())
    return TYPE_ALIASES.get(key, key)


# Status values used across the engine and consumed by the dashboard.
PASS, FAIL, ERROR, SKIPPED = "PASS", "FAIL", "ERROR", "SKIPPED"

PATCH_VERIFIED = "PATCH_VERIFIED"
PATCH_FAILED = "PATCH_FAILED"
REGRESSION_FAILURE = "REGRESSION_FAILURE"
NOT_REPRODUCED = "NOT_REPRODUCED"
VERIFICATION_ERROR = "VERIFICATION_ERROR"
INVALID_FINDING = "INVALID_FINDING"
