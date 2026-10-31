from models import Finding
from patcher import patch_idor, patch_sql_injection, patch_vulnerability, restore_originals


def _finding(code, vtype="SQL_INJECTION", line=None):
    return Finding(id="T", type=vtype, file="x.py", line=line, vulnerable_code=code)


# ---------------------------------------------------------------- SQL injection

def test_sqli_patch_generates_parameterized_query(app_dir, sqli_finding):
    before = (app_dir / "database.py").read_text()
    result = patch_vulnerability(sqli_finding, target_dir=app_dir, apply=False)

    assert result["status"] == "PATCHED"
    assert result["patch_method"] == "PARAMETERIZED_QUERY"
    assert 'query = "SELECT * FROM users WHERE id=?"' in result["patched_code"]
    assert "cursor.execute(query, (user_id,))" in result["patched_code"]
    assert '-    query = "SELECT * FROM users WHERE id=" + user_id' in result["diff"]
    assert '+    query = "SELECT * FROM users WHERE id=?"' in result["diff"]
    # apply=False must not touch the file
    assert (app_dir / "database.py").read_text() == before


def test_sqli_patch_changes_only_the_vulnerable_lines(app_dir, sqli_finding):
    result = patch_vulnerability(sqli_finding, target_dir=app_dir, apply=True)

    assert result["applied"] is True
    changed = [line for change in result["changes"] for line in change["added"]]
    assert len(changed) == 2  # the query line and its execute() call, nothing else
    patched = (app_dir / "database.py").read_text()
    assert '" + user_id' not in patched
    assert "def search_users(term):" in patched  # surrounding code preserved
    assert (app_dir / ".patchproof_backups" / "originals" / "database.py").exists()


def test_sqli_handles_quoted_values_and_fstrings():
    quoted = 'def f(c, name):\n    q = "SELECT * FROM t WHERE name=\'" + name + "\'"\n    c.execute(q)\n'
    patched, _ = patch_sql_injection(quoted, _finding('q = "SELECT'))
    assert 'q = "SELECT * FROM t WHERE name=?"' in patched
    assert "c.execute(q, (name,))" in patched

    fstring = 'def f(c, uid):\n    sql = f"DELETE FROM t WHERE id={uid}"\n    rows = c.execute(sql).fetchall()\n'
    patched, _ = patch_sql_injection(fstring, _finding("sql = f"))
    assert 'sql = "DELETE FROM t WHERE id=?"' in patched
    assert "rows = c.execute(sql, (uid,)).fetchall()" in patched


def test_sqli_refuses_when_execute_call_not_found(tmp_path):
    (tmp_path / "x.py").write_text('def f(uid):\n    q = "SELECT * FROM t WHERE id=" + uid\n    return q\n')
    result = patch_vulnerability(
        {"id": "T", "type": "SQL_INJECTION", "file": "x.py", "vulnerable_code": 'q = "SELECT'}, target_dir=tmp_path
    )
    assert result["status"] == "FAILED"
    assert result["reason"] == "Unable to generate safe patch"


def test_sqli_already_patched_fails(app_dir, sqli_finding):
    assert patch_vulnerability(sqli_finding, target_dir=app_dir)["status"] == "PATCHED"
    assert patch_vulnerability(sqli_finding, target_dir=app_dir)["status"] == "FAILED"


# ---------------------------------------------------------------- IDOR

def test_idor_patch_adds_authorization_check(app_dir, idor_finding):
    result = patch_vulnerability(idor_finding, target_dir=app_dir, apply=True)

    assert result["status"] == "PATCHED"
    assert result["patch_method"] == "AUTHORIZATION_CHECK"
    assert 'if str(user_id) != str(current_user["id"]):' in result["diff"]
    assert "raise HTTPException(status_code=403" in result["diff"]
    added = [line for change in result["changes"] for line in change["added"]]
    assert len(added) == 3 and all(change["action"] == "insert" for change in result["changes"])


def test_idor_already_patched_fails(app_dir, idor_finding):
    assert patch_vulnerability(idor_finding, target_dir=app_dir)["status"] == "PATCHED"
    second = patch_vulnerability(idor_finding, target_dir=app_dir)
    assert second["status"] == "FAILED"
    assert "already present" in second["detail"]


def test_idor_refuses_without_auth_context():
    source = 'from fastapi import FastAPI\napp = FastAPI()\n@app.get("/items/{item_id}")\ndef item(item_id: int):\n    return {}\n'
    finding = Finding(id="T", type="IDOR", file="x.py", evidence={"endpoint": "/items/{item_id}"})
    try:
        patch_idor(source, finding)
    except Exception as exc:
        assert "authenticated-user" in str(exc)
    else:
        raise AssertionError("expected PatchError")


# ---------------------------------------------------------------- safety

def test_path_traversal_and_outside_files_rejected(app_dir, sqli_finding):
    for bad in ["../database.py", "../../etc/passwd", "C:/Windows/win.ini", "README.md"]:
        result = patch_vulnerability({**sqli_finding, "file": bad}, target_dir=app_dir)
        assert result["status"] == "FAILED", bad


def test_unsupported_type_fails(app_dir, sqli_finding):
    result = patch_vulnerability({**sqli_finding, "type": "XSS"}, target_dir=app_dir)
    assert result["status"] == "FAILED"
    assert "unsupported" in result["detail"]


def test_restore_originals(app_dir, sqli_finding, idor_finding):
    originals = {name: (app_dir / name).read_text() for name in ("app.py", "database.py")}
    patch_vulnerability(sqli_finding, target_dir=app_dir)
    patch_vulnerability(idor_finding, target_dir=app_dir)
    assert sorted(restore_originals(app_dir)) == ["app.py", "database.py"]
    assert {name: (app_dir / name).read_text() for name in originals} == originals
