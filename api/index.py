
import os
import re
import hmac
import time
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row
from flask import Flask, request, jsonify, session, redirect, render_template

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static",
)

app.secret_key = os.environ["FLASK_SECRET_KEY"]

DATABASE_URL = os.environ["DATABASE_URL"]
DASHBOARD_PASSWORD = os.environ["DASHBOARD_PASSWORD"]
REGISTRY_ADMIN_TOKEN = os.environ["REGISTRY_ADMIN_TOKEN"]
CLIENT_LOOKUP_KEY = os.environ["CLIENT_LOOKUP_KEY"]

ROOM_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,100}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{30,100}$")


def db():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=10,
    )


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transfer_sessions (
                room TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                transfer_token TEXT NOT NULL,
                updated_at BIGINT NOT NULL
            )
        """)


def valid_tunnel_url(url):
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname is not None
            and parsed.hostname.endswith(".trycloudflare.com")
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


@app.get("/health")
def health():
    try:
        init_db()
        with db() as conn:
            conn.execute("SELECT 1")
        return jsonify(status="ok", database="connected")
    except Exception:
        app.logger.exception("Health check failed")
        return jsonify(error="Service unavailable"), 503


@app.route("/", methods=["GET"])
def home():
    if session.get("logged_in"):
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if hmac.compare_digest(password, DASHBOARD_PASSWORD):
            session.clear()
            session["logged_in"] = True
            return redirect("/dashboard")
        return render_template("login.html", error="Login gagal"), 401

    return render_template("login.html")


@app.post("/logout")
def logout():
    if not session.get("logged_in"):
        return redirect("/login")

    session.clear()
    return redirect("/login")


@app.get("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect("/login")

    try:
        init_db()
        with db() as conn:
            rows = conn.execute("""
                SELECT room, url, updated_at
                FROM transfer_sessions
                WHERE updated_at > %s
                ORDER BY updated_at DESC
            """, (int(time.time()) - 300,)).fetchall()

        return render_template("dashboard.html", sessions=rows)
    except Exception:
        app.logger.exception("Dashboard query failed")
        return "Database sementara tidak tersedia", 503


@app.post("/register")
def register():
    supplied = request.headers.get("X-Admin-Token", "")

    if not hmac.compare_digest(supplied, REGISTRY_ADMIN_TOKEN):
        return jsonify(error="Unauthorized"), 401

    data = request.get_json(silent=True) or {}
    room = data.get("room", "")
    url = data.get("url", "")
    token = data.get("token", "")

    if not isinstance(room, str) or not ROOM_PATTERN.fullmatch(room):
        return jsonify(error="Invalid room"), 400

    if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
        return jsonify(error="Invalid token"), 400

    if not isinstance(url, str) or not valid_tunnel_url(url):
        return jsonify(error="Invalid tunnel URL"), 400

    try:
        init_db()
        now = int(time.time())

        with db() as conn:
            conn.execute("""
                INSERT INTO transfer_sessions
                    (room, url, transfer_token, updated_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (room) DO UPDATE SET
                    url = EXCLUDED.url,
                    transfer_token = EXCLUDED.transfer_token,
                    updated_at = EXCLUDED.updated_at
            """, (room, url, token, now))

        return jsonify(status="registered", updated_at=now)
    except Exception:
        app.logger.exception("Registration failed")
        return jsonify(error="Registry unavailable"), 503


@app.get("/lookup")
def lookup():
    supplied = request.headers.get("X-Lookup-Key", "")

    if not hmac.compare_digest(supplied, CLIENT_LOOKUP_KEY):
        return jsonify(error="Unauthorized"), 401

    room = request.args.get("room", "")

    if not ROOM_PATTERN.fullmatch(room):
        return jsonify(error="Invalid room"), 400

    try:
        init_db()
        with db() as conn:
            row = conn.execute("""
                SELECT url, transfer_token, updated_at
                FROM transfer_sessions
                WHERE room = %s AND updated_at > %s
            """, (room, int(time.time()) - 300)).fetchone()

        if row is None:
            return jsonify(error="Session not found or expired"), 404

        return jsonify(
            url=row["url"],
            token=row["transfer_token"],
        )
    except Exception:
        app.logger.exception("Lookup failed")
        return jsonify(error="Registry unavailable"), 503
