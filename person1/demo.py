"""
End-to-end PATCHPROOF Person 1 demo.

  1. Scan + prove SQL Injection and IDOR against the vulnerable demo app.
  2. Generate findings.json in Person 2's exact schema.
  3. (If Person 2 is present) feed each finding into Person 2's REAL
     remediation pipeline against a throwaway copy of its vulnerable-app and
     show the patch being verified -- without modifying Person 2.

    py -3 demo.py
"""
import json
import shutil
from pathlib import Path

from scanner import person2
from scanner.scanner import FINDINGS_PATH, main


def _run_person2(findings):
    engine = person2.load()
    if engine is None:
        print("\n[i] Person 2 project not found -> skipping live remediation demo.")
        print("    Set PATCHPROOF_PROJECT to Person 2's project root to enable it.")
        return
    print("\n===== PERSON 2 FUNCTIONAL REMEDIATION (real engine, isolated copy) =====")
    for finding in findings:
        copy = person2.fresh_copy()
        try:
            before = engine.run_security_test(finding, target_dir=copy)
            result = engine.full_remediation(finding, target_dir=copy)
            sec = result["verification"]["security_test"]
            reg = result["verification"]["regression_tests"]
            print(f"\n{finding['id']} {finding['type']}")
            print(f"    reproduce attack : {before['status']}")
            print(f"    after patch      : {sec['after']}")
            print(f"    regression       : {reg['status'] if reg else 'n/a'}")
            print(f"    FINAL            : {result['final_status']}")
        finally:
            shutil.rmtree(copy.parent, ignore_errors=True)


if __name__ == "__main__":
    rc = main()

    print("\n----- findings.json (what Person 2 receives) -----")
    data = json.loads(Path(FINDINGS_PATH).read_text(encoding="utf-8"))
    print(json.dumps(data, indent=2))

    _run_person2(data["findings"])
    raise SystemExit(rc)
