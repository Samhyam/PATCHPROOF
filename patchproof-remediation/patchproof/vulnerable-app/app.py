"""
PATCHPROOF demo application -- DELIBERATELY VULNERABLE, local use only.

Intentional vulnerabilities:
  1. SQL injection in GET /users/lookup   (see database.get_user_by_id)
  2. IDOR in GET /profile/{user_id}       (no ownership check)

Run:  uvicorn app:app --app-dir vulnerable-app --port 5000
"""
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

import database

app = FastAPI(title="PATCHPROOF Vulnerable Demo App")
database.init_db()

SESSIONS = {}  # token -> user dict (in-memory, demo only)


class LoginRequest(BaseModel):
    username: str
    password: str


def get_current_user(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ").strip()
    user = SESSIONS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginRequest):
    user = database.authenticate(body.username, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_hex(16)
    SESSIONS[token] = user
    return {"token": token, "user": user}


@app.get("/users/lookup")
def lookup_user(id: str):
    return {"results": database.get_user_by_id(id)}


@app.get("/search")
def search(q: str):
    return {"results": database.search_users(q)}


@app.get("/me")
def me(current_user: dict = Depends(get_current_user)):
    return database.get_profile(current_user["id"])


@app.get("/profile/{user_id}")
def get_profile(user_id: int, current_user: dict = Depends(get_current_user)):
    profile = database.get_profile(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="User not found")
    return profile


@app.get("/users/by-role")
def users_by_role(role: str):
    return {"results": database.get_users_by_role(role)}
