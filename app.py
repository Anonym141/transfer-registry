
import hmac
import os
import re
import secrets
import time
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask, jsonify, redirect, render_template,
    request, session, url_for
)

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "")
if len(app.secret_key) < 32:
    raise RuntimeError("FLASK_SECRET_KEY harus minimal 32 karakter.")

DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
REGISTRY_ADMIN_TOKEN = os.environ.get("REGISTRY_ADMIN_TOKEN", "")
CLIENT_LOOKUP_KEY = os.environ.get("CLIENT_LOOKUP_KEY", "")
SESSION_TTL = 300
MAX_BODY = 4096

if not all((DASHBOARD_PASSWORD, REGISTRY_ADMIN_TOKEN, CLIENT_LOOKUP_KEY)):
    raise RuntimeError("Environment variable wajib belum diatur.")

# Penyimpanan sementara; data hilang saat proses restart.
sessions = {}


def matches(received, expected):
    return bool(received) and hmac.compare_digest(received, expected)


def clean_expired():
    now = time.time()
    expired = [
        room for room, data in sessions.items()
        if now - data["updated"] > SESSION_TTL
    ]
    for room in expired:
        sessions.pop(room, None)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.get("/")
def index():
    return redirect(
        url_for("dashboard" if session.get("logged_in") else "login")
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        if matches(request.form.get("password", ""), DASHBOARD_PASSWORD):
            session.clear()
            session["logged_in"] = True
            session["csrf"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))

        error = "Password salah."

    return render_template("login.html", error=error)


@app.post("/logout")
@login_required
def logout():
    if not matches(
        request.form.get("csrf", ""),
        session.get("csrf", "")
    ):
        return "CSRF validation failed", 400

    session.clear()
    return redirect(url_for("login"))


@app.get("/dashboard")
@login_required
def dashboard():
    clean_expired()
    rows = []

    for room, data in sessions.items():
        rows.append({
            "room": room,
            "url": data["url"],
            "updated": time.strftime(
                "%Y-%m-%d %H:%M:%S UTC",
                time.gmtime(data["updated"])
            )
        })

    return render_template(
        "dashboard.html",
        rows=rows,
        csrf=session.get("csrf", "")
    )


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/register")
def register():
    if not matches(
        request.headers.get("X-Admin-Token", ""),
        REGISTRY_ADMIN_TOKEN
    ):
        return jsonify({"error": "Unauthorized"}), 401

    if request.content_length is None or request.content_length > MAX_BODY:
        return jsonify({"error": "Invalid request size"}), 413

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Expected JSON"}), 400

    room = data.get("room", "")
    url = data.get("url", "")
    token = data.get("token", "")

    if not isinstance(room, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{20,100}", room
    ):
        return jsonify({"error": "Invalid room code"}), 400

    if not isinstance(token, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{30,100}", token
    ):
        return jsonify({"error": "Invalid transfer token"}), 400

    if not isinstance(url, str) or len(url) > 300:
        return jsonify({"error": "Invalid URL"}), 400

    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.hostname.endswith(".trycloudflare.com")
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        return jsonify({"error": "Invalid tunnel URL"}), 400

    sessions[room] = {
        "url": url.rstrip("/"),
        "token": token,
        "updated": time.time()
    }

    return jsonify({"ok": True, "expires_in_seconds": SESSION_TTL})


@app.get("/lookup")
def lookup():
    if not matches(
        request.headers.get("X-Lookup-Key", ""),
        CLIENT_LOOKUP_KEY
    ):
        return jsonify({"error": "Unauthorized"}), 401

    room = request.args.get("room", "")

    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", room):
        return jsonify({"error": "Invalid room code"}), 400

    clean_expired()
    data = sessions.get(room)

    if not data:
        return jsonify({
            "error": "Sender offline or registration expired"
        }), 404

    return jsonify({
        "url": data["url"],
        "token": data["token"]
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
