"""Human-readable diffs and an exact change record for every patch."""
import difflib


def make_diff(original: str, patched: str, filename: str = "") -> str:
    suffix = f"/{filename}" if filename else ""
    lines = difflib.unified_diff(
        original.splitlines(),
        patched.splitlines(),
        fromfile=f"vulnerable{suffix}",
        tofile=f"patched{suffix}",
        n=2,
        lineterm="",
    )
    return "\n".join(lines) + "\n"


def describe_changes(original: str, patched: str) -> list:
    """Return every changed region with 1-based line numbers, removed and added lines."""
    before, after = original.splitlines(), patched.splitlines()
    matcher = difflib.SequenceMatcher(None, before, after, autojunk=False)
    changes = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        changes.append(
            {
                "action": tag,
                "original_lines": [i1 + 1, i2],
                "patched_lines": [j1 + 1, j2],
                "removed": before[i1:i2],
                "added": after[j1:j2],
            }
        )
    return changes
