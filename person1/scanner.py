"""Root entry point so you can run:  py -3 scanner.py  (or: python scanner.py)

This thin launcher defers to scanner/scanner.py (the orchestrator). The
canonical invocation is `py -3 -m scanner.scanner`; both do the same thing.
"""

import importlib.util
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _load_orchestrator():
    # Import scanner/scanner.py by file path to avoid any ambiguity between
    # this launcher file and the scanner/ package of the same name.
    pkg_file = os.path.join(_ROOT, "scanner", "scanner.py")
    spec = importlib.util.spec_from_file_location("scanner.scanner", pkg_file)
    module = importlib.util.module_from_spec(spec)
    # Ensure the parent package 'scanner' is importable for relative imports.
    import scanner as _pkg  # the scanner/ package (dir wins over this file)
    sys.modules.setdefault("scanner", _pkg)
    sys.modules["scanner.scanner"] = module
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    raise SystemExit(_load_orchestrator().main())
