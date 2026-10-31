"""
Optional AI assistance.

AI may explain findings, explain patches and *suggest* a patch when no rule
applies. AI never decides whether a vulnerability is fixed: only the
executable tests in verifier.py and regression.py do that.

Everything works with no API key: each function falls back to deterministic
templates. AI-suggested code is never applied unless PATCHPROOF_ALLOW_AI_PATCH=1,
and even then it must pass static checks, the security test and regression.
"""
import ast
import os
import re

from models import IDOR, SQL_INJECTION, as_finding, normalize_type

MODEL = os.environ.get("PATCHPROOF_AI_MODEL", "claude-sonnet-5-5")

FINDING_TEMPLATES = {
    SQL_INJECTION: (
        "The application builds a database query by gluing user input directly into the SQL text. "
        "An attacker can type SQL instead of an ID (for example '1 OR 1=1') and change what the query "
        "does, such as returning every user instead of one."
    ),
    IDOR: (
        "The application checks that you are logged in, but not that the record you ask for belongs to you. "
        "Changing the ID in the URL lets one user read another user's private data."
    ),
}

PATCH_TEMPLATES = {
    "PARAMETERIZED_QUERY": (
        "The query now uses a placeholder and passes the user input to the database driver separately, "
        "so the input is always treated as data and can never change the SQL statement."
    ),
    "AUTHORIZATION_CHECK": (
        "The endpoint now compares the requested ID with the logged-in user's ID and returns "
        "403 Forbidden when they differ. Users can still open their own records."
    ),
}


def ai_available() -> bool:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def ai_apply_enabled() -> bool:
    return ai_available() and os.environ.get("PATCHPROOF_ALLOW_AI_PATCH") == "1"


def _ask(prompt: str, max_tokens: int = 800):
    if not ai_available():
        return None
    try:
        import anthropic

        client = anthropic.Anthropic(timeout=60)
        message = client.messages.create(
            model=MODEL,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in message.content if getattr(block, "type", "") == "text")
        return text.strip() or None
    except Exception:
        return None  # AI is optional; never let it break remediation


def explain_finding(finding) -> dict:
    finding = as_finding(finding)
    template = FINDING_TEMPLATES.get(normalize_type(finding.type), finding.description)
    text = _ask(
        "Explain this security finding to a non-technical judge in 2-3 plain sentences. "
        f"Type: {finding.type}. Description: {finding.description}. Code: {finding.vulnerable_code}. "
        f"Evidence: {finding.evidence.model_dump()}"
    )
    return {"source": "ai" if text else "template", "text": text or template}


def explain_patch(finding, patch: dict) -> dict:
    template = PATCH_TEMPLATES.get(patch.get("patch_method"), "The vulnerable code was changed; see the diff.")
    text = _ask(
        "In 2 plain sentences, explain what this patch changes and why it fixes the vulnerability. "
        f"Diff:\n{patch.get('diff', '')}"
    )
    return {"source": "ai" if text else "template", "text": text or template}


def suggest_patch(finding, source: str) -> dict:
    """Ask the AI for a full corrected file. The result is untrusted until verified."""
    finding = as_finding(finding)
    if not ai_available():
        return {
            "available": False,
            "source": "none",
            "message": "No rule-based patch and no AI key configured; manual review required.",
            "patched_source": None,
        }
    reply = _ask(
        "You are fixing one security vulnerability in a Python file. Change only what is needed, keep all "
        "other behaviour identical, do not add imports. Reply with one short paragraph explaining the fix, "
        "then the complete corrected file in a single ```python code block.\n\n"
        f"Finding: {finding.model_dump_json()}\n\nFile {finding.file}:\n```python\n{source}\n```",
        max_tokens=4000,
    )
    if not reply:
        return {"available": False, "source": "ai", "message": "AI request failed", "patched_source": None}
    code = re.search(r"```python\n(.*?)```", reply, re.S)
    explanation = reply[: code.start()].strip() if code else reply
    return {
        "available": bool(code),
        "source": "ai",
        "explanation": explanation,
        "patched_source": code.group(1) if code else None,
        "trusted": False,
    }


DANGEROUS_CALLS = {
    "eval", "exec", "compile", "__import__", "system", "popen", "Popen", "run",
    "call", "check_output", "rmtree", "remove", "unlink", "open",
}


def _imports(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
    return names


def _calls(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            names.add(func.id if isinstance(func, ast.Name) else getattr(func, "attr", ""))
    return names


def validate_candidate(original: str, candidate: str):
    """Static gate for AI code before it may even be tested. Returns (ok, reason)."""
    try:
        new_tree, old_tree = ast.parse(candidate), ast.parse(original)
    except SyntaxError as exc:
        return False, f"does not parse: {exc}"
    added_imports = _imports(new_tree) - _imports(old_tree)
    if added_imports:
        return False, f"adds imports {sorted(added_imports)}"
    added_calls = (_calls(new_tree) & DANGEROUS_CALLS) - _calls(old_tree)
    if added_calls:
        return False, f"adds dangerous calls {sorted(added_calls)}"
    if len(candidate) > 3 * len(original) + 2000:
        return False, "suggestion is far larger than the original file"
    return True, "ok"
