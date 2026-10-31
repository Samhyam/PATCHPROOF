"""
Local replica of Person 2's Finding/Evidence contract.

This mirrors patch-engine/models.py (extra="allow" on both models, Evidence.get
falling back to extra fields) so Person 1 can build and self-check findings
without importing Person 2. The authoritative compatibility/integration tests
import Person 2's ACTUAL models and pipeline — see tests/test_compatibility.py
and tests/test_integration.py. Person 1 always emits the canonical type names.
"""
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class Evidence(BaseModel):
    model_config = ConfigDict(extra="allow")

    payload: Optional[str] = None
    result: Optional[str] = None
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


# Person 1 emits only these canonical names (Person 2 also accepts aliases, but
# the clean contract is to send canonical).
CANONICAL_TYPES = {"SQL_INJECTION", "IDOR"}
