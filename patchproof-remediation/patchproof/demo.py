"""
PATCHPROOF judge demo: runs the full workflow for each sample finding.

    python demo.py                      # SQL injection, then IDOR
    python demo.py sample-findings/idor.json
    python demo.py --json               # print the raw result objects
    python demo.py --reset              # restore the vulnerable app and exit

The demo resets vulnerable-app/ first, patches it in place, and leaves the
patched files on disk so you can show them. Run --reset to undo.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "patch-engine"))

from patcher import restore_originals  # noqa: E402
from pipeline import full_remediation  # noqa: E402

DEFAULT_FINDINGS = [ROOT / "sample-findings" / "sql_injection.json", ROOT / "sample-findings" / "idor.json"]
OK, BAD = "✅", "❌"


def show(result):
    sec = result["verification"]["security_test"] or {}
    reg = result["verification"]["regression_tests"]
    patch = result["patch"] or {}
    print("=" * 70)
    print(f"STEP 1  Scanner (Person 1) detected {result['display']['title']} -> {result['id']}")
    print(f"STEP 2  Finding sent to remediation engine ({result['file']})")
    print(f"STEP 3  {result['display']['title']} | {result['severity']} | "
          f"{'Patch Available' if result['display']['patch_available'] else 'No Patch Available'}")
    print(f"        {result['explanation']['text']}")
    if sec.get("before"):
        print(f"        Before patch, attack replay: {'ATTACK SUCCEEDED' if sec['before'] == 'FAIL' else sec['before']}")
    if patch.get("diff"):
        print(f"STEP 4  Patch generated and applied ({patch['method']}):")
        print("        " + patch["diff"].rstrip().replace("\n", "\n        "))
    elif patch:
        print(f"STEP 4  Patch FAILED: {patch.get('detail')}")
    if sec.get("after"):
        verdict = f"ATTACK BLOCKED {OK}" if sec["after"] == "PASS" else f"ATTACK STILL WORKS {BAD}"
        print(f"STEP 5  Original payload replayed: {sec['payload']}")
        print(f"        Result: {verdict}  ({sec['message']})")
    if reg:
        print("STEP 6  Regression tests:")
        for test in reg["tests"]:
            print(f"        {test['name']:<26} {test['status']}")
    mark = OK if result["final_status"] == "PATCH_VERIFIED" else BAD
    print(f"STEP 7  FINAL STATUS: {result['final_status'].replace('_', ' ')} {mark}")
    print()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("findings", nargs="*", type=Path, help="finding JSON files")
    parser.add_argument("--json", action="store_true", help="print raw JSON results")
    parser.add_argument("--reset", action="store_true", help="restore the vulnerable app and exit")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    restored = restore_originals()
    if args.reset:
        print(f"Restored: {restored or 'nothing to restore'}")
        return

    for path in args.findings or DEFAULT_FINDINGS:
        result = full_remediation(json.loads(path.read_text(encoding="utf-8")))
        print(json.dumps(result, indent=2)) if args.json else show(result)


if __name__ == "__main__":
    main()
