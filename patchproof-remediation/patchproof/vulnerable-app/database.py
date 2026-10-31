"""
Database layer for the PATCHPROOF demo application.

WARNING: this file is DELIBERATELY VULNERABLE for a local hackathon demo.
Never deploy it. get_user_by_id() builds SQL with string concatenation.
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


def get_users_by_role(role):
    """List users by role. VULNERABLE: SQL injection via string concatenation."""
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT id, username, full_name FROM users WHERE role='" + role + "'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return [{field: row[field] for field in PUBLIC_FIELDS} for row in rows]
