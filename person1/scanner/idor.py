"""
IDOR / Broken Access Control scanner: find + prove against the live app.

FIND  -> locate a route handler with an object-id path parameter (e.g.
         /profile/{user_id}) that authenticates the caller but performs no
         ownership check.
PROVE -> log in as user A (real seeded credentials), request user B's resource,
         and confirm B's private data comes back with HTTP 200.

Emits a finding with a BARE filename ("app.py") and structured evidence
(attacker credentials + victim_id) that Person 2's verifier replays directly.
"""
import ast
import re
from pathlib import Path

from .appload import parse_seed_users
from .models import Evidence, Finding

METHOD = "GET"
_ROUTE_DECORATORS = {"get", "post", "put", "patch", "delete", "route", "api_route"}


def _find_idor_route(app_path: Path):
    """Return (endpoint, def_line_no, def_source) for a route handler that takes
    an authenticated user AND an object-id path param (the IDOR shape)."""
    try:
        source = app_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return None, None, ""

    lines = source.splitlines()
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
        if not path or not re.search(r"\{\w+(:\w+)?\}", path):
            continue
        # Handler must receive an authenticated-user dependency (has auth) ...
        text = ast.get_source_segment(source, node) or ""
        has_user = bool(re.search(r"current_user|get_current_user|Depends\(", text))
        if not has_user:
            continue
        return path, node.lineno, lines[node.lineno - 1].strip()
    return None, None, ""


def scan(client, app_dir, finding_id="VULN-002"):
    """Return (Finding | None, log_lines)."""
    log = []
    app_dir = Path(app_dir)

    users = parse_seed_users(app_dir)
    if len(users) < 2:
        log.append("could not find two demo accounts to run the IDOR test")
        return None, log
    attacker, victim = users[0], users[1]
    victim_id = victim["id"]

    endpoint, line_no, code = _find_idor_route(app_dir / "app.py")
    endpoint = endpoint or "/profile/{user_id}"

    login = client.post("/login", json={"username": attacker["username"], "password": attacker["password"]})
    if login.status_code != 200 or not login.json().get("token"):
        log.append(f"login as {attacker['username']} failed (HTTP {login.status_code})")
        return None, log
    token = login.json()["token"]
    log.append(f"logged in as {attacker['username']} (id={attacker['id']})")

    victim_url = re.sub(r"\{\w+(:\w+)?\}", str(victim_id), endpoint, count=1)
    resp = client.get(victim_url, headers={"Authorization": f"Bearer {token}"})
    log.append(f"GET {victim_url} as {attacker['username']} -> HTTP {resp.status_code}")

    if resp.status_code != 200:
        log.append("IDOR NOT confirmed (access denied)")
        return None, log
    try:
        body = resp.json()
    except ValueError:
        body = {}
    leaked_id = body.get("id") if isinstance(body, dict) else None
    private = body.get("email") or body.get("role") if isinstance(body, dict) else None
    confirmed = leaked_id == victim_id and attacker["id"] != victim_id and bool(private)
    if not confirmed:
        log.append("IDOR NOT confirmed (no cross-user private data returned)")
        return None, log
    log.append("IDOR CONFIRMED exploitable")

    if not code:
        code = "def get_profile(user_id: int, current_user: dict = Depends(get_current_user)):"

    result = (
        f"User '{attacker['username']}' (id {attacker['id']}) read user {victim_id} "
        f"('{body.get('username')}') private profile with HTTP 200. "
        f"Leaked: email={body.get('email')!r}, role={body.get('role')!r}"
    )

    finding = Finding(
        id=finding_id,
        type="IDOR",
        severity="HIGH",
        file="app.py",
        line=line_no,
        description=(
            f"The {endpoint} endpoint authenticates the caller but never checks "
            "that the caller owns the requested record. Any logged-in user can "
            "read another user's private profile by changing the id in the URL."
        ),
        vulnerable_code=code,
        evidence=Evidence(
            payload=f"GET {victim_url} while logged in as {attacker['username']} (user {attacker['id']})",
            result=result,
            endpoint=endpoint,
            method=METHOD,
            attacker={"username": attacker["username"], "password": attacker["password"]},
            victim_id=victim_id,
        ),
    )
    return finding, log
