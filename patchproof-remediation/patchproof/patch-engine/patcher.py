"""
PATCHPROOF patch engine (rule-based, deterministic).

    patch_vulnerability(finding) -> patch result dict

Each supported vulnerability type has one small rule registered in PATCHERS.
A rule receives the original source and the finding and returns
(patched_source, meta), or raises PatchError when it cannot produce a patch it
is sure about. To support a new vulnerability type, write a rule with the same
signature and register it in PATCHERS.

Safety:
  * only .py files inside the target (demo) directory can be modified
  * path traversal and absolute paths outside the target are rejected
  * every change is backed up before the file is written
  * a patch is only reported as PATCHED if the code actually changed and compiles
"""
import ast
import os
import re
import shutil
import time
from pathlib import Path

from diff_generator import describe_changes, make_diff
from models import IDOR, SQL_INJECTION, as_finding, normalize_type

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_TARGET_DIR = ROOT_DIR / "vulnerable-app"
BACKUP_DIR_NAME = ".patchproof_backups"


class PatchError(Exception):
    """Raised when a rule cannot produce a patch it is confident is safe."""


# --------------------------------------------------------------------------- #
# File handling
# --------------------------------------------------------------------------- #

def get_target_dir(target_dir=None) -> Path:
    chosen = target_dir or os.environ.get("PATCHPROOF_TARGET_DIR") or DEFAULT_TARGET_DIR
    return Path(chosen).resolve()


def resolve_target_file(target_dir, file_ref: str) -> Path:
    """Map a finding's 'file' to a real file inside the target dir, or raise PatchError."""
    base = get_target_dir(target_dir)
    if not file_ref:
        raise PatchError("finding has no 'file'")
    ref = Path(file_ref.replace("\\", "/"))
    if ref.is_absolute():
        candidate = ref.resolve()
    else:
        parts = ref.parts
        if parts and parts[0] == base.name:  # scanner sent "vulnerable-app/database.py"
            ref = Path(*parts[1:]) if len(parts) > 1 else Path("")
        if ".." in ref.parts:
            raise PatchError(f"path traversal rejected: {file_ref}")
        candidate = (base / ref).resolve()
    if base not in candidate.parents:
        raise PatchError(f"file is outside the demo project directory: {file_ref}")
    if BACKUP_DIR_NAME in candidate.parts:
        raise PatchError("refusing to patch backup files")
    if candidate.suffix != ".py":
        raise PatchError(f"only Python files can be patched: {file_ref}")
    if not candidate.is_file():
        raise PatchError(f"file not found: {file_ref}")
    return candidate


def read_source(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _write_source(path: Path, source: str):
    tmp = path.with_name(path.name + ".patchproof-tmp")
    tmp.write_bytes(source.encode("utf-8"))
    os.replace(tmp, path)


def apply_patch(path: Path, new_source: str, target_dir=None) -> Path:
    """Back up the file (pristine copy + timestamped copy), then write the patch."""
    base = get_target_dir(target_dir)
    rel = path.resolve().relative_to(base)
    backup_root = base / BACKUP_DIR_NAME
    original_copy = backup_root / "originals" / rel
    if not original_copy.exists():
        original_copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, original_copy)
    stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{time.time_ns() % 1_000_000:06d}"
    history_copy = backup_root / "history" / rel.parent / f"{rel.name}.{stamp}.bak"
    history_copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, history_copy)
    _write_source(path, new_source)
    return history_copy


def rollback_patch(file_ref: str, backup: str, target_dir=None):
    """Restore a file from the backup taken just before it was patched."""
    base = get_target_dir(target_dir)
    path = resolve_target_file(base, file_ref)
    backup_path = Path(backup).resolve()
    if (base / BACKUP_DIR_NAME).resolve() not in backup_path.parents:
        raise PatchError("backup is outside the backup directory")
    _write_source(path, read_source(backup_path))


def restore_originals(target_dir=None) -> list:
    """Undo every patch ever applied to the target dir (demo reset)."""
    base = get_target_dir(target_dir)
    backup_root = base / BACKUP_DIR_NAME
    originals = backup_root / "originals"
    restored = []
    if originals.is_dir():
        for copy in sorted(originals.rglob("*")):
            if copy.is_file():
                rel = copy.relative_to(originals)
                _write_source(base / rel, read_source(copy))
                restored.append(str(rel).replace("\\", "/"))
    shutil.rmtree(backup_root, ignore_errors=True)
    shutil.rmtree(base / "__pycache__", ignore_errors=True)
    return restored


# --------------------------------------------------------------------------- #
# Small source helpers
# --------------------------------------------------------------------------- #

def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _ending(line: str) -> str:
    return line[len(line.rstrip("\r\n")):] or "\n"


def _norm(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def _py_str(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _locate_line(lines, finding, predicate, max_distance=15) -> int:
    """Find the vulnerable line: match the reported code first, then the line hint."""
    candidates = [i for i, line in enumerate(lines) if predicate(line)]
    wanted = _norm(finding.vulnerable_code)
    exact = [i for i in candidates if wanted and (wanted in _norm(lines[i]) or _norm(lines[i]) in wanted)]
    pool = exact or candidates
    if not pool:
        raise PatchError("vulnerable code not found in file (already patched?)")
    if finding.line:
        best = min(pool, key=lambda i: abs(i + 1 - finding.line))
        if not exact and abs(best + 1 - finding.line) > max_distance:
            raise PatchError("no vulnerable code near the reported line")
        return best
    if len(pool) == 1:
        return pool[0]
    raise PatchError("several candidate lines and no line number; refusing to guess")


# --------------------------------------------------------------------------- #
# Rule 1: SQL injection -> parameterized query
# --------------------------------------------------------------------------- #

SQL_START = re.compile(r"^\s*(SELECT|INSERT|UPDATE|DELETE|REPLACE)\b", re.IGNORECASE)


def _flatten_sql_expr(node):
    """Split '"SQL" + x' / f"SQL{x}" into [("str", text) | ("expr", source)] parts."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_sql_expr(node.left) + _flatten_sql_expr(node.right)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [("str", node.value)]
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(("str", value.value))
            elif value.conversion != -1 or value.format_spec is not None:
                raise PatchError("f-string conversions/format specs are not supported")
            else:
                parts.append(("expr", ast.unparse(value.value)))
        return parts
    return [("expr", ast.unparse(node))]


def _parse_sql_assignment(line: str):
    """Return (variable, parts) if the line builds SQL from user input, else None."""
    try:
        tree = ast.parse(line.strip())
    except SyntaxError:
        return None
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.Assign):
        return None
    stmt = tree.body[0]
    if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
        return None
    if not isinstance(stmt.value, (ast.BinOp, ast.JoinedStr)):
        return None
    try:
        parts = _flatten_sql_expr(stmt.value)
    except PatchError:
        return None
    if not parts or parts[0][0] != "str" or not SQL_START.match(parts[0][1]):
        return None
    if not any(kind == "expr" for kind, _ in parts):
        return None
    return stmt.targets[0].id, parts


def _parameterize(parts, placeholder):
    """Turn the parts into (sql_with_placeholders, [param_expressions])."""
    parts = [list(p) for p in parts]
    sql, params = "", []
    for i, (kind, text) in enumerate(parts):
        if kind == "str":
            sql += text
            continue
        nxt = parts[i + 1] if i + 1 < len(parts) and parts[i + 1][0] == "str" else None
        open_quote = re.search(r"(['\"])(%*)$", sql)
        if open_quote:
            # Value was wrapped in quotes in the SQL text, e.g. name='" + name + "'
            close_quote = re.match(r"(%*)(['\"])", nxt[1]) if nxt else None
            if not close_quote or close_quote.group(2) != open_quote.group(1):
                raise PatchError("unbalanced quotes around user input")
            prefix, suffix = open_quote.group(2), close_quote.group(1)
            sql = sql[: open_quote.start()]
            nxt[1] = nxt[1][close_quote.end():]
            pieces = ([_py_str(prefix)] if prefix else []) + [f"str({text})" if prefix or suffix else text]
            pieces += [_py_str(suffix)] if suffix else []
            params.append(" + ".join(pieces))
        else:
            params.append(text)
        sql += placeholder
    if placeholder == "%s" and sql.replace("%s", "").count("%"):
        raise PatchError("literal % in query would clash with %s placeholders")
    return sql, params


def patch_sql_injection(source: str, finding):
    lines = source.splitlines(keepends=True)
    idx = _locate_line(lines, finding, lambda line: _parse_sql_assignment(line) is not None)
    var, parts = _parse_sql_assignment(lines[idx])
    uses_pyformat = re.search(r"^\s*(import|from)\s+(psycopg2?|pymysql|MySQLdb|mysql)\b", source, re.M)
    placeholder = "%s" if uses_pyformat else "?"
    sql, params = _parameterize(parts, placeholder)

    # Find the execute() call that consumes the query, inside the same block.
    indent = _indent(lines[idx])
    exec_re = re.compile(r"^(?P<pre>.*?\.execute\(\s*)" + re.escape(var) + r"(?P<post>\s*\).*)$")
    exec_idx = None
    for j in range(idx + 1, min(len(lines), idx + 40)):
        body = lines[j].rstrip("\r\n")
        if body.strip() and len(_indent(body)) < len(indent):
            break
        if re.match(r"^\s*" + re.escape(var) + r"\s*(\+=|=)", body):
            raise PatchError("query variable is modified after construction; refusing to guess")
        if exec_re.match(body):
            exec_idx = j
            break
    if exec_idx is None:
        raise PatchError(f"could not find the execute({var}) call that runs the query")

    param_tuple = f"({params[0]},)" if len(params) == 1 else f"({', '.join(params)})"
    match = exec_re.match(lines[exec_idx].rstrip("\r\n"))
    new_assign = f"{indent}{var} = {_py_str(sql)}{_ending(lines[idx])}"
    new_exec = f"{match.group('pre')}{var}, {param_tuple}{match.group('post')}{_ending(lines[exec_idx])}"

    original_snippet = [lines[idx].strip(), lines[exec_idx].strip()]
    lines[idx], lines[exec_idx] = new_assign, new_exec
    meta = {
        "line": idx + 1,
        "execute_line": exec_idx + 1,
        "original_code": "\n".join(original_snippet),
        "patched_code": "\n".join([new_assign.strip(), new_exec.strip()]),
    }
    return "".join(lines), meta


# --------------------------------------------------------------------------- #
# Rule 2: IDOR -> object-level authorization check
# --------------------------------------------------------------------------- #

ROUTE_DECORATORS = {"get", "post", "put", "patch", "delete", "route", "api_route"}


def _route_path(func):
    for dec in func.decorator_list:
        if (
            isinstance(dec, ast.Call)
            and isinstance(dec.func, ast.Attribute)
            and dec.func.attr in ROUTE_DECORATORS
            and dec.args
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            return dec.args[0].value
    return None


def _path_matches(route: str, endpoint: str) -> bool:
    route_parts = route.strip("/").split("/")
    endpoint_parts = endpoint.split("?")[0].strip("/").split("/")
    if len(route_parts) != len(endpoint_parts):
        return False
    return all(r == e or (r.startswith("{") and r.endswith("}")) for r, e in zip(route_parts, endpoint_parts))


def _params_with_defaults(func):
    args = func.args
    positional = args.posonlyargs + args.args
    defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    return list(zip(positional, defaults)) + list(zip(args.kwonlyargs, args.kw_defaults))


def _current_user_param(func):
    """The handler argument injected by an auth dependency, e.g. Depends(get_current_user)."""
    for arg, default in _params_with_defaults(func):
        if (
            isinstance(default, ast.Call)
            and isinstance(default.func, ast.Name)
            and default.func.id in ("Depends", "Security")
        ):
            dependency = ast.unparse(default.args[0]) if default.args else ""
            if "user" in arg.arg.lower() or "user" in dependency.lower():
                return arg.arg
    return None


def _ensure_fastapi_import(source: str, name: str) -> str:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "fastapi":
            if any(alias.name == name for alias in node.names):
                return source
    lines = source.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if re.match(r"^from fastapi import [^()\\]+$", line.rstrip("\r\n")):
            lines[i] = line.rstrip("\r\n") + f", {name}" + _ending(line)
            return "".join(lines)
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    at = imports[-1].end_lineno if imports else 0
    lines.insert(at, f"from fastapi import {name}\n")
    return "".join(lines)


def patch_idor(source: str, finding):
    tree = ast.parse(source)
    routes = [
        (node, _route_path(node))
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    routes = [(node, path) for node, path in routes if path and re.search(r"\{\w+(:\w+)?\}", path)]
    if not routes:
        raise PatchError("no route with a path parameter found")

    endpoint = finding.evidence.get("endpoint")
    if not endpoint:
        match = re.search(r"[\"'](/[^\"']*\{\w+\}[^\"']*)[\"']", finding.vulnerable_code or "")
        endpoint = match.group(1) if match else None
    matches = [node for node, path in routes if endpoint and _path_matches(path, endpoint)]
    if not matches and finding.line:
        matches = [
            node for node, _ in routes
            if min([d.lineno for d in node.decorator_list] + [node.lineno]) <= finding.line <= node.end_lineno
        ]
    if not matches and finding.vulnerable_code:
        wanted = _norm(finding.vulnerable_code)
        matches = [node for node, _ in routes if wanted and wanted in _norm(ast.get_source_segment(source, node))]
    if len(matches) != 1:
        raise PatchError("could not identify exactly one vulnerable route handler")
    func = matches[0]

    arg_names = {arg.arg for arg, _ in _params_with_defaults(func)}
    id_params = [p for p in re.findall(r"\{(\w+)(?::\w+)?\}", _route_path(func)) if p in arg_names]
    if not id_params:
        raise PatchError("route has no object-id path parameter")
    id_param = next((p for p in id_params if p.lower().endswith("id")), id_params[-1])
    user_param = _current_user_param(func)
    if not user_param:
        raise PatchError("handler has no authenticated-user dependency; cannot add a safe ownership check")

    func_source = ast.get_source_segment(source, func)
    for line in func_source.splitlines():
        if re.search(rf"\b{id_param}\b", line) and re.search(rf"\b{user_param}\b", line) and re.search(r"[!=]=", line):
            raise PatchError("authorization check already present")

    access = f"{user_param}.id" if re.search(rf"\b{user_param}\.id\b", source) else f'{user_param}["id"]'
    body = func.body
    has_docstring = (
        isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    )
    first = body[1] if has_docstring and len(body) > 1 else body[0]
    lines = source.splitlines(keepends=True)
    anchor = lines[first.lineno - 1]
    if first.lineno == func.lineno or anchor.lstrip().startswith(("def ", "async def ")):
        raise PatchError("single-line handlers are not supported")
    ind, end = _indent(anchor), _ending(anchor)
    check = [
        f"{ind}# PATCHPROOF: object-level authorization check (IDOR fix){end}",
        f"{ind}if str({id_param}) != str({access}):{end}",
        f'{ind}    raise HTTPException(status_code=403, detail="Forbidden: you can only access your own resources"){end}',
    ]
    signature = lines[func.lineno - 1].strip()
    lines[first.lineno - 1:first.lineno - 1] = check
    patched = _ensure_fastapi_import("".join(lines), "HTTPException")
    meta = {
        "line": first.lineno,
        "handler": func.name,
        "original_code": "\n".join([signature, anchor.strip()]),
        "patched_code": "\n".join([signature] + [c.rstrip("\r\n") for c in check] + [anchor.rstrip("\r\n")]),
    }
    return patched, meta


# --------------------------------------------------------------------------- #
# Registry + public API
# --------------------------------------------------------------------------- #

PATCHERS = {
    SQL_INJECTION: (patch_sql_injection, "PARAMETERIZED_QUERY"),
    IDOR: (patch_idor, "AUTHORIZATION_CHECK"),
}


def _failed(finding, reason):
    return {
        "status": "FAILED",
        "vulnerability_id": getattr(finding, "id", None),
        "reason": "Unable to generate safe patch",
        "detail": reason,
    }


def build_patch_result(finding, path, target_dir, original, patched, method, source, meta=None, apply=True):
    """Validate a candidate patch, record exactly what changed and optionally apply it."""
    if patched == original:
        raise PatchError("patch produced no change")
    try:
        compile(patched, str(path), "exec")
    except SyntaxError as exc:
        raise PatchError(f"patched code does not compile: {exc}") from exc
    base = get_target_dir(target_dir)
    rel = str(path.relative_to(base)).replace("\\", "/")
    changes = describe_changes(original, patched)
    meta = meta or {}
    result = {
        "status": "PATCHED",
        "vulnerability_id": finding.id,
        "type": normalize_type(finding.type),
        "file": rel,
        "original_code": meta.get("original_code") or "\n".join(l for c in changes for l in c["removed"]),
        "patched_code": meta.get("patched_code") or "\n".join(l for c in changes for l in c["added"]),
        "diff": make_diff(original, patched, rel),
        "patch_method": method,
        "source": source,
        "changes": changes,
        "applied": False,
    }
    if apply:
        backup = apply_patch(path, patched, base)
        result["applied"] = True
        result["backup"] = str(backup)
    return result


def patch_vulnerability(finding, target_dir=None, apply=True) -> dict:
    """Generate (and by default apply) a patch for one finding."""
    try:
        finding = as_finding(finding)
    except Exception as exc:  # pydantic ValidationError, TypeError, ...
        return _failed(None, f"invalid finding: {exc}")
    vuln_type = normalize_type(finding.type)
    if vuln_type not in PATCHERS:
        return _failed(finding, f"unsupported vulnerability type: {finding.type}")
    rule, method = PATCHERS[vuln_type]
    try:
        path = resolve_target_file(target_dir, finding.file)
        original = read_source(path)
        patched, meta = rule(original, finding)
        return build_patch_result(finding, path, target_dir, original, patched, method, "RULE_BASED", meta, apply)
    except PatchError as exc:
        return _failed(finding, str(exc))
