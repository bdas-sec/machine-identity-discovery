#!/usr/bin/env python3
"""
Vulnerable Application - NHI Security Testbed
NDC Security 2026 - "Who Gave the Agent Admin Rights?!"

WARNING: This application contains INTENTIONAL security vulnerabilities
for demonstration purposes. DO NOT use in production.

Vulnerabilities demonstrated:
- V1: Exposed .env file via web endpoint
- V2: Hardcoded credentials in source code
- V3: Environment variables exposed via /debug endpoint
- V4: Secrets in git history
"""

import os
import subprocess
from flask import Flask, jsonify, request, send_file

app = Flask(__name__)

# ============================================================
# VULNERABILITY V2: Hardcoded credentials in source code
# These are FAKE credentials for demonstration
# ============================================================
HARDCODED_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
HARDCODED_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
HARDCODED_DB_PASSWORD = "admin123_super_secret"
HARDCODED_API_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"


# ============================================================
# VULNERABILITY V3: Configuration class with secrets
# ============================================================
class Config:
    """Application configuration - INTENTIONALLY INSECURE"""
    SECRET_KEY = "super-secret-flask-key-do-not-use"
    DATABASE_URL = "postgresql://admin:password123@db.internal:5432/app"
    REDIS_PASSWORD = "redis_secret_pass_123"
    JWT_SECRET = "jwt-signing-key-very-secret"


@app.route("/")
def index():
    """Home page"""
    return jsonify({
        "app": "NHI Vulnerable Demo App",
        "version": "1.0.0",
        "warning": "This app contains INTENTIONAL vulnerabilities",
        "endpoints": {
            "/": "This page",
            "/health": "Health check",
            "/.env": "VULNERABLE: Exposed .env file",
            "/debug": "VULNERABLE: Debug info with env vars",
            "/config": "VULNERABLE: Exposed configuration",
            "/git-history": "VULNERABLE: Git commit history"
        }
    })


@app.route("/health")
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy"})


# ============================================================
# VULNERABILITY V1: .env file exposed via web
# Real attack: Misconfigured web server serving dotfiles
# ============================================================
@app.route("/.env")
@app.route("/.env.local")
@app.route("/.env.production")
def expose_env_file():
    """
    VULNERABLE: Serves the .env file directly
    This simulates a misconfigured web server that doesn't
    block access to dotfiles.
    """
    env_file = "/app/.env"
    if os.path.exists(env_file):
        return send_file(env_file, mimetype="text/plain")
    return "File not found", 404


# ============================================================
# VULNERABILITY V3: Environment variables exposed
# ============================================================
@app.route("/debug")
def debug_info():
    """
    VULNERABLE: Exposes all environment variables
    This is a common misconfiguration in debug endpoints.
    """
    # Filter to show interesting env vars (simulated attack success)
    interesting_vars = {}
    for key, value in os.environ.items():
        if any(x in key.upper() for x in [
            "KEY", "SECRET", "PASSWORD", "TOKEN", "API",
            "AWS", "GITHUB", "DATABASE", "CREDENTIAL"
        ]):
            interesting_vars[key] = value

    return jsonify({
        "warning": "DEBUG ENDPOINT - SHOULD NOT BE IN PRODUCTION",
        "environment_variables": interesting_vars,
        "all_env_count": len(os.environ)
    })


# ============================================================
# VULNERABILITY V2: Hardcoded credentials exposed
# ============================================================
@app.route("/config")
def expose_config():
    """
    VULNERABLE: Exposes hardcoded configuration values
    """
    return jsonify({
        "warning": "CONFIGURATION EXPOSED - INTENTIONALLY VULNERABLE",
        "aws": {
            "access_key": HARDCODED_AWS_KEY,
            "secret_key": HARDCODED_AWS_SECRET[:10] + "...(truncated in response)"
        },
        "database": {
            "password": HARDCODED_DB_PASSWORD
        },
        "api_tokens": {
            "github": HARDCODED_API_TOKEN[:20] + "..."
        },
        "flask_config": {
            "secret_key": Config.SECRET_KEY,
            "database_url": Config.DATABASE_URL
        }
    })


# ============================================================
# VULNERABILITY V4: Git history with secrets
# ============================================================
@app.route("/git-history")
def git_history():
    """
    VULNERABLE: Shows git history which may contain secrets
    This simulates the attack of finding secrets in git history
    """
    try:
        # Get git log with patches
        result = subprocess.run(
            ["git", "log", "--all", "-p", "--max-count=5"],
            capture_output=True,
            text=True,
            cwd="/app",
            timeout=5
        )
        return jsonify({
            "warning": "GIT HISTORY MAY CONTAIN SECRETS",
            "git_log": result.stdout[:5000] if result.stdout else "No history",
            "hint": "Look for removed secrets in the diff output"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# VULNERABILITY: /proc filesystem access demonstration
# ============================================================
@app.route("/proc/<int:pid>/environ")
def read_proc_environ(pid):
    """
    VULNERABLE: Demonstrates reading /proc/<pid>/environ
    This is how attackers extract secrets from process memory
    """
    try:
        if pid == 0:
            pid = os.getpid()

        environ_path = f"/proc/{pid}/environ"
        if os.path.exists(environ_path):
            with open(environ_path, "rb") as f:
                content = f.read()
            # Parse null-separated environment variables
            env_vars = content.decode("utf-8", errors="ignore").split("\x00")
            return jsonify({
                "warning": "PROCESS ENVIRONMENT EXTRACTED",
                "pid": pid,
                "environment": [e for e in env_vars if e]
            })
        return jsonify({"error": "Process not found"}), 404
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Load .env file (makes secrets available as env vars)
    from dotenv import load_dotenv
    load_dotenv("/app/.env")

    print("=" * 50)
    print("WARNING: This is an INTENTIONALLY VULNERABLE app")
    print("DO NOT expose to untrusted networks!")
    print("=" * 50)

    app.run(host="0.0.0.0", port=8080, debug=True)
