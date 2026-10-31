"""
SQL Injection scanner: find + prove against the live demo app.

FIND  -> locate a SQL statement built by string concatenation / f-string in the
         target's database.py, with a user-controlled value spliced in.
PROVE -> send a benign request and a tautology payload through the real HTTP
         stack; confirm the payload defeats the WHERE filter (more rows) or
         triggers a SQL error.

Emits a finding with a BARE filename (e.g. "database.py") so Person 2's
resolve_target_file maps it straight into its own vulnerable-app.
"""
import ast
from pathlib import Path

from .models import Evidence, Finding

PAYLOAD = "1 OR 1=1"
BASELINE = "1"
ENDPOINT = "/users/lookup"
PARAMETER = "id"
METHOD = "GET"

_SQL_START = ("select", "insert", "update", "delete", "replace")


def _count(resp):
    try:
        data = resp.json()
    except ValueError:
        return 0
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return len(data["results"])
    if isinstance(data, list):
        return len(data)
    return 1 if data else 0


def _locate_concat_sql(db_path: Path):
    """Return (line_no, source_text) for a SQL string built with concatenation or
    an f-string from a variable, or (None, '')."""
    try:
        source = db_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return None, ""

    def is_sql_literal(node):
        return (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.strip().lower().startswith(_SQL_START)
        )

    def builds_sql(value):
        # "SELECT ..." + x
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            left = value
            while isinstance(left, ast.BinOp):
                left = left.left
            return is_sql_literal(left)
        # f"SELECT ...{x}..." with an interpolated expression
        if isinstance(value, ast.JoinedStr):
            text = "".join(
                v.value for v in value.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
            has_expr = any(isinstance(v, ast.FormattedValue) for v in value.values)
            return text.strip().lower().startswith(_SQL_START) and has_expr
        return False

    lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and builds_sql(node.value):
            ln = node.lineno
            return ln, lines[ln - 1].strip()
    return None, ""


def scan(client, app_dir, finding_id="VULN-001"):
    """Return (Finding | None, log_lines)."""
    log = []
    app_dir = Path(app_dir)

    baseline = client.get(ENDPOINT, params={PARAMETER: BASELINE})
    attack = client.get(ENDPOINT, params={PARAMETER: PAYLOAD})
    base_n, atk_n = _count(baseline), _count(attack)
    log.append(f"baseline {PARAMETER}={BASELINE} -> HTTP {baseline.status_code}, {base_n} row(s)")
    log.append(f"payload {PARAMETER}='{PAYLOAD}' -> HTTP {attack.status_code}, {atk_n} row(s)")

    exploited = attack.status_code == 200 and atk_n > base_n
    sql_error = attack.status_code >= 500
    if not (exploited or sql_error):
        log.append("SQL injection NOT confirmed")
        return None, log

    if exploited:
        try:
            names = [r.get("username") for r in attack.json().get("results", [])]
        except ValueError:
            names = []
        result = (
            f"Unexpected records returned: tautology payload returned {atk_n} rows "
            f"vs {base_n} for a single id. Leaked usernames: {names}"
        )
    else:
        result = "Payload caused a server error: input reaches the SQL parser"
    log.append("SQL injection CONFIRMED exploitable")

    line_no, code = _locate_concat_sql(app_dir / "database.py")
    if not code:
        code = 'query = "SELECT * FROM users WHERE id=" + user_id'

    finding = Finding(
        id=finding_id,
        type="SQL_INJECTION",
        severity="HIGH",
        file="database.py",
        line=line_no,
        description=(
            "User input is concatenated directly into a SQL query in "
            "get_user_by_id(), allowing SQL injection. A tautology payload "
            "bypasses the WHERE filter and returns every user record."
        ),
        vulnerable_code=code,
        evidence=Evidence(
            payload=PAYLOAD,
            result=result,
            endpoint=ENDPOINT,
            method=METHOD,
            parameter=PARAMETER,
        ),
    )
    return finding, log


# --------------------------------------------------------------------------- #
# Multi-endpoint discovery scan (used by the live /scan API and demo)
# --------------------------------------------------------------------------- #

# A value that should match no rows and (for unquoted/numeric columns) break the
# SQL syntax — useful both as a benign baseline and as an error-based probe.
_NOMATCH = "__patchproof_nomatch__"
_INJECTION_PAYLOADS = ["1 OR 1=1", "' OR '1'='1", "x' OR '1'='1"]
_ROUTE_DECORATORS = {"get"}


def _discover_get_endpoints(app_path: Path):
    """Parse app.py and return [(endpoint, query_param, db_func)] for GET routes
    that have no path parameter and take a single user-controlled query arg."""
    try:
        source = app_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []

    results = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        path = None
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and dec.func.attr in _ROUTE_DECORATORS
                and dec.args
                and isinstance(dec.args[0], ast.Constant)
                and isinstance(dec.args[0].value, str)
            ):
                path = dec.args[0].value
                break
        if not path or "{" in path:
            continue

        # A query param = a plain arg with no Depends/Header/Security default.
        args = node.args
        positional = args.posonlyargs + args.args
        defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
        query_param = None
        for arg, default in zip(positional, defaults):
            if isinstance(default, ast.Call) and isinstance(default.func, ast.Name) and \
               default.func.id in ("Depends", "Header", "Security"):
                continue
            query_param = arg.arg
            break
        if not query_param:
            continue

        # Which database.<func>() the handler calls (for source mapping).
        db_func = None
        for sub in ast.walk(node):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Attribute)
                and isinstance(sub.func.value, ast.Name)
                and sub.func.value.id == "database"
            ):
                db_func = sub.func.attr
                break
        results.append((path, query_param, db_func))
    return results


def _locate_in_func(db_path: Path, func_name):
    """Find the concat/f-string SQL line inside a specific db function."""
    if not func_name:
        return _locate_concat_sql(db_path)
    try:
        source = db_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return None, ""
    lines = source.splitlines()

    def builds_sql(value):
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            left = value
            while isinstance(left, ast.BinOp):
                left = left.left
            return (isinstance(left, ast.Constant) and isinstance(left.value, str)
                    and left.value.strip().lower().startswith(_SQL_START))
        if isinstance(value, ast.JoinedStr):
            text = "".join(v.value for v in value.values
                           if isinstance(v, ast.Constant) and isinstance(v.value, str))
            has_expr = any(isinstance(v, ast.FormattedValue) for v in value.values)
            return text.strip().lower().startswith(_SQL_START) and has_expr
        return False

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign) and builds_sql(sub.value):
                    return sub.lineno, lines[sub.lineno - 1].strip()
    return _locate_concat_sql(db_path)


def scan_all(client, app_dir):
    """Discover and prove SQL injection across every GET endpoint. Returns
    (list[Finding], log). Findings have placeholder ids; the caller renumbers."""
    app_dir = Path(app_dir)
    log = []
    findings = []
    endpoints = _discover_get_endpoints(app_dir / "app.py")
    log.append(f"discovered {len(endpoints)} GET endpoint(s) to probe")

    for endpoint, param, db_func in endpoints:
        none_n = _count(client.get(endpoint, params={param: _NOMATCH}))
        hit_payload = None
        hit_n = None
        server_error = False
        for payload in _INJECTION_PAYLOADS:
            resp = client.get(endpoint, params={param: payload})
            if resp.status_code >= 500:
                server_error = True
                hit_payload = payload
                break
            n = _count(resp)
            if resp.status_code == 200 and n > none_n and n > 1:
                hit_payload, hit_n = payload, n
                break

        if not hit_payload:
            log.append(f"{endpoint} ?{param}= : not injectable")
            continue

        if server_error:
            result = "Payload caused a server error: input reaches the SQL parser"
        else:
            result = (f"Unexpected records returned: payload returned {hit_n} rows "
                      f"vs {none_n} for a non-matching value")
        log.append(f"{endpoint} ?{param}= : SQL injection CONFIRMED ({hit_payload})")

        line_no, code = _locate_in_func(app_dir / "database.py", db_func)
        findings.append(Finding(
            type="SQL_INJECTION",
            severity="HIGH",
            file="database.py",
            line=line_no,
            description=(
                f"User input '{param}' is concatenated directly into SQL in "
                f"{db_func or 'the query'}(), allowing SQL injection via {endpoint}."
            ),
            vulnerable_code=code or "query = ... + " + param,
            evidence=Evidence(
                payload=hit_payload,
                baseline_value=_NOMATCH,
                result=result,
                endpoint=endpoint,
                method="GET",
                parameter=param,
            ),
            id="SQLI",
        ))
    return findings, log
