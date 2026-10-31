"""
Regression tests: prove the patch did not break normal functionality.

Each check runs real HTTP requests against the freshly loaded app. A check is
SKIPPED (not passed) when the app does not expose the routes it needs, so the
suite adapts to whatever endpoints the target application has.
"""
from models import ERROR, FAIL, PASS, SKIPPED
from verifier import TestClient, load_app

# Demo accounts from vulnerable-app/database.py (fake data).
DEMO_ACCOUNTS = {
    "alice": {"password": "alice123", "id": 1, "email": "alice@example.test"},
    "bob": {"password": "bob123", "id": 2, "email": "bob@example.test"},
}


def _check(condition, message):
    if not condition:
        raise AssertionError(message)


def _login(client, username):
    account = DEMO_ACCOUNTS[username]
    r = client.post("/login", json={"username": username, "password": account["password"]})
    _check(r.status_code == 200 and r.json().get("token"), f"login as {username} returned HTTP {r.status_code}")
    return {"Authorization": f"Bearer {r.json()['token']}"}


def check_login(client):
    _login(client, "alice")
    bad = client.post("/login", json={"username": "alice", "password": "wrong"})
    _check(bad.status_code == 401, f"wrong password should be rejected, got HTTP {bad.status_code}")
    return "valid login accepted, wrong password rejected"


def check_user_lookup(client):
    for username, account in DEMO_ACCOUNTS.items():
        r = client.get("/users/lookup", params={"id": str(account["id"])})
        _check(r.status_code == 200, f"lookup id={account['id']} returned HTTP {r.status_code}")
        results = r.json().get("results", [])
        _check(len(results) == 1 and results[0]["username"] == username,
               f"lookup id={account['id']} expected [{username}], got {results}")
    return "lookup by id returns exactly the requested user"


def check_search(client):
    r = client.get("/search", params={"q": "ali"})
    _check(r.status_code == 200, f"search returned HTTP {r.status_code}")
    names = [u["username"] for u in r.json().get("results", [])]
    _check("alice" in names, f"search 'ali' should find alice, got {names}")
    return "search finds matching users"


def check_profile_access(client):
    headers = _login(client, "alice")
    r = client.get("/profile/1", headers=headers)
    _check(r.status_code == 200, f"alice viewing own profile returned HTTP {r.status_code}")
    _check(r.json().get("email") == DEMO_ACCOUNTS["alice"]["email"], "own profile has wrong data")
    return "users can open their own profile"


def check_legitimate_authorization(client):
    headers = _login(client, "bob")
    r = client.get("/profile/2", headers=headers)
    _check(r.status_code == 200 and r.json().get("id") == 2, f"bob viewing own profile returned HTTP {r.status_code}")
    me = client.get("/me", headers=headers)
    _check(me.status_code == 200 and me.json().get("id") == 2, f"/me for bob returned HTTP {me.status_code}")
    anonymous = client.get("/profile/2")
    _check(anonymous.status_code == 401, f"anonymous request should get 401, got {anonymous.status_code}")
    return "owners keep access, anonymous users are rejected"


# (name, routes the check needs, check function)
REGRESSION_TESTS = [
    ("Login", ["/login"], check_login),
    ("Normal user lookup", ["/users/lookup"], check_user_lookup),
    ("Search", ["/search"], check_search),
    ("Profile access", ["/login", "/profile/{user_id}"], check_profile_access),
    ("Legitimate authorization", ["/login", "/profile/{user_id}", "/me"], check_legitimate_authorization),
]


def run_regression_tests(target_dir=None) -> dict:
    try:
        app = load_app(target_dir)
    except Exception as exc:
        return {"status": ERROR, "message": f"App failed to load: {exc!r}", "tests": [], "passed": 0, "failed": 1}

    routes = {getattr(route, "path", None) for route in app.routes}
    tests = []
    with TestClient(app, raise_server_exceptions=False) as client:
        for name, needed, check in REGRESSION_TESTS:
            if not set(needed) <= routes:
                tests.append({"name": name, "status": SKIPPED, "message": f"app has no {sorted(set(needed) - routes)}"})
                continue
            try:
                tests.append({"name": name, "status": PASS, "message": check(client)})
            except AssertionError as exc:
                tests.append({"name": name, "status": FAIL, "message": str(exc)})
            except Exception as exc:
                tests.append({"name": name, "status": FAIL, "message": f"error: {exc!r}"})

    passed = sum(t["status"] == PASS for t in tests)
    failed = sum(t["status"] == FAIL for t in tests)
    skipped = sum(t["status"] == SKIPPED for t in tests)
    return {
        "status": PASS if failed == 0 and passed > 0 else FAIL,
        "tests": tests,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
    }
