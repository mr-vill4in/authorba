#!/usr/bin/env python3
#
# Author: Mr_Vill4in
# -*- coding: utf-8 -*-
"""
vuln_server.py - deliberately vulnerable web app for testing the Authorba
Burp extension. FOR LOCAL TESTING ONLY.

Contains:
  * /api/login                     - session login (cookie-based), /api/token (JWT)
  * /api/orders/<id>               - BOLA: any authenticated user reads any order
  * /api/admin/delete-user         - BFLA: admin function, no role check
  * /api/admin/export-audit       - BFLA #2: properly protected (contrast case)
  * /api/users/<id>                - BOPLA: leaks password_hash + salary fields
  * /api/users/<id>/profile       - properly protected property endpoint
  * /api/orders                    - properly protected listing (own orders only)
  * /graphql                       - minimal GraphQL-ish endpoint (query/mutation)
  * /api/public/health             - PUBLIC: no auth needed (three-state test)
  * /api/admin/soft-denied        - 200 + "forbidden" body (content-verdict test)
  * /api/reports                   - WAF/RL: 403 with WAF body (infra-block test)
  * /static/* + /favicon.ico       - static noise the extension should skip

Roles: admin, user, viewer
Users:
  admin  / admin123   (role=admin)
  alice  / alice123   (role=user)
  bob    / bob123     (role=user)
  eve    / eve123     (role=viewer)

Canary suggestions: each user's email (e.g. alice@corp.local) - leaked via
/api/users/<id> and order owner names via /api/orders/<id>.

Run:  python3 vuln_server.py [port]     (default 5000, listens on 127.0.0.1)
"""
import base64
import hashlib
import hmac
import json
import time
import sys

from flask import Flask, request, jsonify, Response

app = Flask(__name__, static_folder=None)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
JWT_SECRET = b"super-secret-do-not-use"

# ---------------------------------------------------------------------------
# fake data
# ---------------------------------------------------------------------------
USERS = {
    "admin": {"id": 1, "password": "admin123", "role": "admin",
              "email": "admin@corp.local", "salary": 0,
              "password_hash": hashlib.md5("admin123".encode()).hexdigest()},
    "alice": {"id": 2, "password": "alice123", "role": "user",
              "email": "alice@corp.local", "salary": 85000,
              "password_hash": hashlib.md5("alice123".encode()).hexdigest()},
    "bob":   {"id": 3, "password": "bob123", "role": "user",
              "email": "bob@corp.local", "salary": 72000,
              "password_hash": hashlib.md5("bob123".encode()).hexdigest()},
    "eve":   {"id": 4, "password": "eve123", "role": "viewer",
              "email": "eve@corp.local", "salary": 58000,
              "password_hash": hashlib.md5("eve123".encode()).hexdigest()},
}

ORDERS = {
    1001: {"id": 1001, "owner": "alice", "item": "laptop",   "total": 1299.99},
    1002: {"id": 1002, "owner": "bob",   "item": "phone",    "total": 699.00},
    1003: {"id": 1003, "owner": "admin", "item": "server",   "total": 9800.00},
    1004: {"id": 1004, "owner": "eve",   "item": "keyboard", "total": 89.50},
}

SESSIONS = {}  # token -> username

DELETED = set()


# ---------------------------------------------------------------------------
# auth helpers
# ---------------------------------------------------------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(username, role):
    hdr = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pl = b64url(json.dumps({
        "sub": username, "role": role,
        "iat": int(time.time()), "exp": int(time.time()) + 3600,
    }).encode())
    sig = b64url(hmac.new(JWT_SECRET, ("%s.%s" % (hdr, pl)).encode(),
                          hashlib.sha256).digest())
    return "%s.%s.%s" % (hdr, pl, sig)


def current_user():
    """Auth via session cookie 'session' OR Authorization: Bearer <jwt>."""
    tok = request.cookies.get("session")
    if tok and tok in SESSIONS:
        return USERS[SESSIONS[tok]]
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            hdr, pl, sig = auth[7:].split(".")
            expect = b64url(hmac.new(JWT_SECRET, ("%s.%s" % (hdr, pl)).encode(),
                                     hashlib.sha256).digest())
            if hmac.compare_digest(sig, expect):
                payload = json.loads(base64.urlsafe_b64decode(pl + "=" * (-len(pl) % 4)))
                if payload.get("exp", 0) > time.time():
                    return USERS.get(payload["sub"])
        except Exception:
            pass
    return None


def require_auth():
    u = current_user()
    if u is None:
        return None, (jsonify({"error": "unauthenticated"}), 401)
    return u, None


def require_role(*roles):
    u, err = require_auth()
    if err:
        return None, err
    if u["role"] not in roles:
        return None, (jsonify({"error": "forbidden", "role": u["role"]}), 403)
    return u, None


# ---------------------------------------------------------------------------
# auth endpoints (for session refresh testing)
# ---------------------------------------------------------------------------
@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or request.form or {}
    if not d and request.get_data():
        # parse urlencoded bodies even without the correct Content-Type
        # (browsers/raw Burp requests often omit it)
        try:
            from urllib.parse import parse_qs
            parsed = parse_qs(request.get_data().decode("utf-8"))
            d = {k: v[0] for k, v in parsed.items()}
        except Exception:
            d = {}
    username, password = d.get("username"), d.get("password")
    u = USERS.get(username or "")
    if not u or u["password"] != password:
        return jsonify({"error": "bad credentials"}), 401
    tok = hashlib.sha256(("%s-%f" % (username, time.time())).encode()).hexdigest()[:32]
    SESSIONS[tok] = username
    resp = jsonify({"ok": True, "role": u["role"], "session": tok})
    resp.set_cookie("session", tok, httponly=True)
    return resp


@app.post("/api/logout")
def logout():
    tok = request.cookies.get("session")
    if tok:
        SESSIONS.pop(tok, None)
    return jsonify({"ok": True})


def username_of(u):
    for name, v in USERS.items():
        if v is u:
            return name
    return "?"


@app.get("/api/token")
def token():
    """Issue a JWT for the logged-in user (so you can test Bearer users)."""
    u = current_user()
    if u is None:
        return jsonify({"error": "unauthenticated"}), 401
    return jsonify({"access_token": make_jwt(username_of(u), u["role"]),
                    "token_type": "Bearer"})


@app.get("/api/whoami")
def whoami():
    u = current_user()
    if u is None:
        return jsonify({"error": "unauthenticated"}), 401
    return jsonify({"username": username_of(u), "role": u["role"]})


# ---------------------------------------------------------------------------
# BOLA - broken object level authorization
# ---------------------------------------------------------------------------
@app.get("/api/orders/<int:oid>")
def get_order(oid):
    """VULNERABLE: any authenticated user can read ANY order.
    Correct behavior would check order['owner'] == current username."""
    u, err = require_auth()
    if err:
        return err
    order = ORDERS.get(oid)
    if not order:
        return jsonify({"error": "not found"}), 404
    # BUG: missing check: if order["owner"] != username -> 403
    return jsonify(order)


@app.delete("/api/orders/<int:oid>")
def delete_order(oid):
    """VULNERABLE (BOLA, destructive): any authenticated user can delete any order."""
    u, err = require_auth()
    if err:
        return err
    if oid not in ORDERS:
        return jsonify({"error": "not found"}), 404
    ORDERS.pop(oid)
    return jsonify({"ok": True, "deleted": oid})


@app.get("/api/orders")
def list_orders():
    """SAFE contrast case: only your own orders."""
    u, err = require_auth()
    if err:
        return err
    username = username_of(u)
    mine = [o for o in ORDERS.values() if o["owner"] == username]
    return jsonify({"orders": mine, "server_time": time.time()})


# ---------------------------------------------------------------------------
# BFLA - broken function level authorization
# ---------------------------------------------------------------------------
@app.post("/api/admin/delete-user")
def admin_delete_user():
    """VULNERABLE: admin-only function with NO role check (only auth)."""
    u, err = require_auth()
    if err:
        return err
    # BUG: missing check: if u["role"] != "admin" -> 403
    d = request.get_json(silent=True) or {}
    DELETED.add(d.get("username", "?"))
    return jsonify({"ok": True, "deleted_user": d.get("username"), "by_role": u["role"]})


@app.get("/api/admin/export-audit")
def export_audit():
    """SAFE contrast case: admin-only, actually enforced."""
    u, err = require_role("admin")
    if err:
        return err
    return jsonify({"audit": ["admin logged in", "order 1001 created"],
                    "generated_at": time.time()})


@app.get("/api/admin/stats")
def admin_stats():
    """VULNERABLE (BFLA): role check is client-side only - server never checks."""
    u, err = require_auth()
    if err:
        return err
    return jsonify({"total_users": len(USERS), "total_orders": len(ORDERS),
                    "revenue": 11888.49})


# ---------------------------------------------------------------------------
# BOPLA - broken object property level authorization
# ---------------------------------------------------------------------------
@app.get("/api/users/<int:uid>")
def get_user(uid):
    """VULNERABLE: returns password_hash and salary to ANY authenticated user.
    Correct behavior would strip those fields for non-admin/self requests."""
    u, err = require_auth()
    if err:
        return err
    target = next((v for v in USERS.values() if v["id"] == uid), None)
    if not target:
        return jsonify({"error": "not found"}), 404
    # BUG: leaking sensitive properties wholesale
    return jsonify({
        "id": target["id"], "email": target["email"],
        "role": target["role"],
        "password_hash": target["password_hash"],   # <-- should never leave server
        "salary": target["salary"],                 # <-- admin/self only
    })


@app.get("/api/users/<int:uid>/profile")
def get_user_profile(uid):
    """SAFE contrast case: only safe fields exposed."""
    u, err = require_auth()
    if err:
        return err
    target = next((v for v in USERS.values() if v["id"] == uid), None)
    if not target:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": target["id"], "email": target["email"]})


# ---------------------------------------------------------------------------
# minimal GraphQL-ish endpoint (query + mutation, no real schema engine)
# ---------------------------------------------------------------------------
@app.post("/graphql")
def graphql():
    body = request.get_json(silent=True) or {}
    q = (body.get("query") or "").strip()
    u, err = require_auth()
    if err:
        return err

    if q.startswith("mutation"):
        # VULNERABLE: any user can run admin mutations
        m = __import__("re").search(r"deleteUser|purge", q)
        if m:
            return jsonify({"data": {"mutation": m.group(0), "ok": True,
                                     "executed_by_role": u["role"]}})
        return jsonify({"errors": [{"message": "unknown mutation"}]}), 400

    if "orders" in q or "order" in q:
        # VULNERABLE: returns all orders regardless of ownership
        return jsonify({"data": {"orders": list(ORDERS.values()),
                                 "requested_by_role": u["role"]}})
    if "me" in q:
        return jsonify({"data": {"me": {"role": u["role"], "email": u["email"]}}})
    return jsonify({"data": {}})


# ---------------------------------------------------------------------------
# verdict-exercise endpoints for the new Authorba checks
# ---------------------------------------------------------------------------
@app.get("/api/public/health")
def public_health():
    """PUBLIC: no auth at all - the unauth probe should match the baseline,
    so this endpoint renders light-blue PUBLIC, never a FINDING."""
    return jsonify({"status": "ok", "service": "vuln-server", "ts": time.time()})


@app.get("/api/admin/soft-denied")
def soft_denied():
    """Content-based denial: HTTP 200 but the body says forbidden. Authorba's
    denial-marker regex should classify this BLOCKED despite the 200."""
    u, err = require_auth()
    if err:
        return err
    if u["role"] != "admin":
        return jsonify({"error": "forbidden", "detail": "insufficient privileges",
                        "user_role": u["role"]}), 200
    return jsonify({"admin_data": "welcome, admin"})


@app.get("/api/reports")
def reports():
    """WAF/rate-limit simulation: 403 whose body matches WAF phrases. Should
    be classified violet WAF/RL, not green ENFORCED."""
    u, err = require_auth()
    if err:
        return err
    body = ("<html><body>Access to this page has been denied. "
            "Request throttled - rate limit exceeded. "
            "Incident ID 8f3a-2211. [Cloudflare]</body></html>")
    return Response(body, status=403, mimetype="text/html")


# ---------------------------------------------------------------------------
# static noise (extension should skip these)
# ---------------------------------------------------------------------------
@app.get("/static/<path:p>")
def static_file(p):
    css = "body{font-family:sans-serif}"
    js = "console.log('app boot');"
    return Response((css if p.endswith(".css") else js) if p.endswith((".css", ".js"))
                    else "asset", mimetype="text/plain")


@app.get("/favicon.ico")
def favicon():
    return Response(b"\x00\x00\x01\x00", mimetype="image/x-icon")


@app.get("/")
def index():
    return jsonify({"app": "vuln-server", "docs": "see vuln_server.py docstring",
                    "users": {k: v["password"] for k, v in USERS.items()}})


if __name__ == "__main__":
    print("=" * 70)
    print(" VULN SERVER (for Authorba testing) on http://127.0.0.1:%d" % PORT)
    print(" Logins:  admin/admin123  alice/alice123  bob/bob123  eve/eve123")
    print(" Configure Burp proxy -> browse http://127.0.0.1:%d/ and the API" % PORT)
    print("=" * 70)
    app.run(host="127.0.0.1", port=PORT, debug=False)
