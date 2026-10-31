"""
PATCHPROOF Person 1 scanner — orchestrator and entry point.

Scans a vulnerable demo app (Person 2's own vulnerable-app when it can be found,
otherwise the bundled copy), actually exploits SQL Injection and IDOR over the
real HTTP stack, and writes findings.json in the exact schema Person 2 consumes.

Run:  py -3 scanner.py    (or: py -3 -m scanner.scanner)
"""
import json
from pathlib import Path

from . import config, idor, person2, sqli
from .appload import app_client
from .models import CANONICAL_TYPES, Finding

FINDINGS_PATH = config.PERSON1_ROOT / "findings.json"


def _person2_finding_model():
    """Return Person 2's ACTUAL Finding class if the project can be located."""
    engine = person2.load()
    return engine.Finding if engine else None


def run_scan(scan_target=None):
    """Exploit the target app and return the list of confirmed Findings."""
    scan_target = Path(scan_target) if scan_target else config.find_scan_target()
    findings = []

    print("PATCHPROOF SECURITY SCANNER")
    print("=" * 42)
    print(f"[i] scanning app: {scan_target}")

    with app_client(scan_target) as (client, copy_dir):
        print("\n[+] SQL Injection scan")
        sqli_findings, log1 = sqli.scan_all(client, copy_dir)
        for line in log1:
            print(f"    - {line}")
        if sqli_findings:
            print(f"[+] SQL Injection found and proven ({len(sqli_findings)} endpoint(s))")
            findings.extend(sqli_findings)
        else:
            print("[ ] SQL Injection not confirmed")

        print("\n[+] IDOR scan")
        f2, log2 = idor.scan(client, copy_dir)
        for line in log2:
            print(f"    - {line}")
        if f2:
            print("[+] IDOR found and proven")
            findings.append(f2)
        else:
            print("[ ] IDOR not confirmed")

    # Assign stable sequential ids (VULN-001, VULN-002, ...).
    for i, finding in enumerate(findings, start=1):
        finding.id = f"VULN-{i:03d}"

    return findings


def write_findings(findings, path=FINDINGS_PATH):
    payload = {"findings": [f.model_dump(exclude_none=True) for f in findings]}
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def main():
    findings = run_scan()
    path = write_findings(findings)
    print(f"\n[+] findings.json generated -> {path}")

    # Self-check against the local replica of Person 2's contract.
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for item in data["findings"]:
        model = Finding.model_validate(item)
        assert model.type in CANONICAL_TYPES, f"non-canonical type {model.type}"

    # Stronger check: validate against Person 2's ACTUAL Finding model if present.
    p2_finding = _person2_finding_model()
    if p2_finding is not None:
        for item in data["findings"]:
            p2_finding.model_validate(item)
        print("[+] findings compatible with Person 2 (validated against its real Finding model)")
    else:
        print("[i] Person 2 project not found; validated against local contract replica only")
        print("    (set PATCHPROOF_PROJECT to Person 2's project root for the full check)")

    print(f"[+] {len(findings)} finding(s) written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
