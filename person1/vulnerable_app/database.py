"""
Bundled copy of the PATCHPROOF demo database layer.

This mirrors Person 2's vulnerable-app/database.py EXACTLY (same seed users,
same vulnerable line) so that when Person 1 scans this bundled app standalone,
the findings it emits (bare filename `database.py`, real line, real code) are
directly valid against Person 2's remediation engine.

Person 1's scanner prefers to scan Person 2's own vulnerable-app when it can
find it; this bundled copy is only a fallback for running standalone.

WARNING: DELIBERATELY VULNERABLE, local use only. Do NOT patch it here —
patching is Person 2's job.
"""
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo.db")

# Demo-only seed data (fake users, fake passwords).
SEED_USERS = [
    (1, "alice", "alice123", "alice@example.test", "Alice Anderson", "user"),
    (2, "bob", "bob123", "bob@example.test", "Bob Brown", "user"),
    (3, "carol", "carol123", "carol@example.test", "Carol Clark", "admin"),
]

PUBLIC_FIELDS = ("id", "username", "full_name")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, "
        "password TEXT NOT NULL, email TEXT, full_name TEXT, role TEXT)"
    )
    cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", SEED_USERS)
    conn.commit()
    conn.close()


def get_user_by_id(user_id):
    """Look up a user by id. VULNERABLE: SQL injection via string concatenation."""
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return [{field: row[field] for field in PUBLIC_FIELDS} for row in rows]


def authenticate(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role FROM users WHERE username=? AND password=?",
        (username, password),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def search_users(term):
    conn = get_connection()
    cursor = conn.cursor()
    pattern = "%" + term + "%"
    cursor.execute(
        "SELECT id, username, full_name FROM users WHERE username LIKE ? OR full_name LIKE ?",
        (pattern, pattern),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_profile(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email, full_name, role FROM users WHERE id=?", (user_id,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None
