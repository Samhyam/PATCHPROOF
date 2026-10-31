"""
Security verifier -- the source of truth for PATCHPROOF.

It loads the target application fresh from disk and replays the exploit from
the finding through the real HTTP stack (FastAPI TestClient, in-process, no
network). A result is PASS only if the attack was actually executed and was
actually denied. Errors are reported as ERROR, never as PASS.
"""
import contextlib
import importlib
import re
import shutil
import sys
import threading
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore")  # newer Starlette warns about its httpx-based TestClient
    from fastapi.testclient import TestClient

from models import ERROR, FAIL, IDOR, PASS, SQL_INJECTION, as_finding, normalize_type
from patcher import get_target_dir

_LOAD_LOCK = threading.RLock()


def load_app(target_dir=None, module_name="app", attribute="app"):
    """Import the target app from disk, bypassing any cached/old version of it."""
    base = get_target_dir(target_dir)
    shutil.rmtree(base / "__pycache__", ignore_errors=True)
    local_names = {p.stem for p in base.glob("*.py")}
    with _LOAD_LOCK:
        saved = {name: sys.modules.pop(name) for name in local_names if name in sys.modules}
        old_flag = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(base))
        importlib.invalidate_caches()
        try:
            module = importlib.import_module(module_name)
            return getattr(module, attribute)
        finally:
            sys.path.remove(str(base))
            sys.dont_write_bytecode = old_flag
            for name in local_names:
                sys.modules.pop(name, None)
            sys.modules.update(saved)


@contextlib.contextmanager
def app_client(target_dir=None):
    app = load_app(target_dir)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def _safe_endpoint(endpoint: str) -> str:
    # Only paths on the local demo app; never full URLs.
    if not endpoint.startswith("/") or endpoint.startswith("//") or "://" in endpoint:
        raise ValueError(f"endpoint must be a local path, got {endpoint!r}")
    return endpoint


def _count_records(response) -> int:
    try:
        data = response.json()
    except ValueError:
        return 0
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return len(data["results"])
    if isinstance(data, list):
        return len(data)
    return 1 if data else 0


def _send(client, method, endpoint, parameter, value):
    if method == "GET":
        return client.get(endpoint, params={parameter: value})
    return client.request(method, endpoint, json={parameter: value})


# --------------------------------------------------------------------------- #
# Exploit replays
# --------------------------------------------------------------------------- #

def test_sql_injection(client, finding) -> dict:
    """Replay the injection payload and compare against a benign request."""
    ev = finding.evidence
    payload = ev.get("payload", "1 OR 1=1")
    endpoint = _safe_endpoint(ev.get("endpoint", "/users/lookup"))
    method = ev.get("method", "GET").upper()
    parameter = ev.get("parameter", "id")
    benign_value = str(ev.get("baseline_value", "1"))

    baseline = _send(client, method, endpoint, parameter, benign_value)
    attack = _send(client, method, endpoint, parameter, payload)
    baseline_n, attack_n = _count_records(baseline), _count_records(attack)
    details = {
        "endpoint": endpoint,
        "baseline_records": baseline_n,
        "attack_records": attack_n,
        "attack_http_status": attack.status_code,
    }
    if attack.status_code >= 500:
        status, message = FAIL, "Payload caused a server error: input still reaches the SQL parser"
    elif attack.status_code == 200 and attack_n > baseline_n:
        status = FAIL
        message = f"SQL Injection succeeded: payload returned {attack_n} records (normal request: {baseline_n})"
    else:
        status, message = PASS, "SQL Injection blocked"
    return {"status": status, "payload": payload, "message": message, "details": details}


def test_idor(client, finding) -> dict:
    """Log in as the attacker and request the victim's resource."""
    ev = finding.evidence
    attacker = ev.get("attacker", {"username": "alice", "password": "alice123"})
    victim_id = ev.get("victim_id", 2)
    login_endpoint = _safe_endpoint(ev.get("login_endpoint", "/login"))
    endpoint = _safe_endpoint(ev.get("endpoint", "/profile/{user_id}"))
    url = re.sub(r"\{\w+(:\w+)?\}", str(victim_id), endpoint, count=1)
    payload = f"{attacker['username']} requests GET {url} (user {victim_id}'s resource)"

    login = client.post(login_endpoint, json=attacker)
    token = login.json().get("token") if login.status_code == 200 else None
    if not token:
        return {
            "status": ERROR,
            "payload": payload,
            "message": f"Could not log in as attacker (HTTP {login.status_code}); test not executed",
        }

    response = client.get(url, headers={"Authorization": f"Bearer {token}"})
    details = {"endpoint": url, "attack_http_status": response.status_code}
    if response.status_code in (401, 403, 404):
        return {"status": PASS, "payload": payload, "message": "Unauthorized access blocked", "details": details}
    if response.status_code == 200:
        try:
            body = response.json()
        except ValueError:
            body = None
        leaked_id = body.get("id") if isinstance(body, dict) else None
        details["leaked_record_id"] = leaked_id
        message = f"IDOR succeeded: attacker read user {victim_id}'s data (HTTP 200)"
        return {"status": FAIL, "payload": payload, "message": message, "details": details}
    return {
        "status": FAIL,
        "payload": payload,
        "message": f"Request was not denied (HTTP {response.status_code})",
        "details": details,
    }


SECURITY_TESTS = {
    SQL_INJECTION: test_sql_injection,
    IDOR: test_idor,
}


def run_security_test(finding, target_dir=None) -> dict:
    """Execute the original attack against the current code on disk."""
    finding = as_finding(finding)
    vuln_type = normalize_type(finding.type)
    test = SECURITY_TESTS.get(vuln_type)
    if test is None:
        return {"status": ERROR, "message": f"No executable security test for {finding.type}"}
    try:
        with app_client(target_dir) as client:
            result = test(client, finding)
    except Exception as exc:  # app failed to import, bad endpoint, ...
        return {"status": ERROR, "message": f"Security test could not run: {exc!r}"}
    result["vulnerability_id"] = finding.id
    result["type"] = vuln_type
    return result


# Keep pytest from collecting the replay functions if this module is imported in tests.
test_sql_injection.__test__ = False
test_idor.__test__ = False
