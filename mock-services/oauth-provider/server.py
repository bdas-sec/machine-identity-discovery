#!/usr/bin/env python3
"""
Mock OAuth2/OIDC Provider
NDC Security 2026 - NHI Security Testbed

Simulates OAuth2 authorization server for demonstrating
consent phishing and token theft attacks (T1550.001).

Endpoints:
- /.well-known/openid-configuration  - OIDC discovery
- /.well-known/jwks.json             - JWKS public keys
- /authorize                          - Authorization (consent screen)
- /oauth/token                        - Token exchange
- /oauth/token/introspect             - Token introspection
- /userinfo                           - OIDC userinfo
- /health                             - Health check

All tokens returned are FAKE and for demonstration only.
"""

import os
import json
import uuid
import base64
import hashlib
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock-oauth")

# Configuration from environment
OAUTH_PORT = int(os.environ.get("OAUTH_PORT", 8090))
OAUTH_ISSUER = os.environ.get("OAUTH_ISSUER", "http://mock-oauth:8090")
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "demo-malicious-app")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "demo-client-secret-FAKE")

# Generate RSA key pair at startup for JWT signing
_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
_public_key = _private_key.public_key()

# Key ID for JWKS
_kid = hashlib.sha256(
    _public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
).hexdigest()[:16]

# In-memory stores for demo
_authorization_codes = {}
_refresh_tokens = {}


def log_access(endpoint: str, source_ip: str):
    """Log all OAuth access for monitoring"""
    logger.warning(f"OAUTH ACCESS: {source_ip} -> {endpoint}")


def _encode_int(value: int) -> str:
    """Encode integer as base64url for JWKS."""
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def _build_jwks() -> dict:
    """Build JWKS document from public key."""
    pub_numbers = _public_key.public_numbers()
    return {
        "keys": [{
            "kty": "RSA",
            "kid": _kid,
            "use": "sig",
            "alg": "RS256",
            "n": _encode_int(pub_numbers.n),
            "e": _encode_int(pub_numbers.e)
        }]
    }


def _sign_token(claims: dict) -> str:
    """Sign a JWT with the server's RSA private key."""
    return jwt.encode(claims, _private_key, algorithm="RS256", headers={"kid": _kid})


# ============================================================
# OIDC Discovery Endpoints
# ============================================================

@app.route("/.well-known/openid-configuration")
def oidc_discovery():
    """
    OpenID Connect Discovery Document
    Attackers use this to understand the OAuth provider's capabilities
    """
    log_access("/.well-known/openid-configuration", request.remote_addr)
    logger.warning(f"[ATTACK] OIDC discovery accessed from {request.remote_addr} - reconnaissance")

    return jsonify({
        "issuer": OAUTH_ISSUER,
        "authorization_endpoint": f"{OAUTH_ISSUER}/authorize",
        "token_endpoint": f"{OAUTH_ISSUER}/oauth/token",
        "introspection_endpoint": f"{OAUTH_ISSUER}/oauth/token/introspect",
        "userinfo_endpoint": f"{OAUTH_ISSUER}/userinfo",
        "jwks_uri": f"{OAUTH_ISSUER}/.well-known/jwks.json",
        "response_types_supported": ["code", "token"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": [
            "openid", "profile", "email",
            "admin:org", "repo", "repo:write",
            "user:email", "read:org", "workflow"
        ],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"]
    })


@app.route("/.well-known/jwks.json")
def jwks():
    """
    JSON Web Key Set
    Public keys used to verify JWT signatures
    """
    log_access("/.well-known/jwks.json", request.remote_addr)
    return jsonify(_build_jwks())


# ============================================================
# Authorization Endpoint - Consent Phishing
# ============================================================

@app.route("/authorize")
def authorize():
    """
    OAuth2 Authorization Endpoint - CONSENT PHISHING SIMULATION

    In a real attack:
    1. Attacker creates malicious OAuth app
    2. Victim clicks phishing link to this endpoint
    3. Consent screen shows broad permissions
    4. Victim approves, attacker gets authorization code
    5. Attacker exchanges code for access token
    """
    log_access("/authorize", request.remote_addr)

    client_id = request.args.get("client_id", OAUTH_CLIENT_ID)
    redirect_uri = request.args.get("redirect_uri", "https://attacker.example.com/callback")
    scope = request.args.get("scope", "admin:org repo user:email")
    state = request.args.get("state", str(uuid.uuid4()))
    response_type = request.args.get("response_type", "code")

    logger.warning(
        f"[ATTACK] OAuth consent phishing attempt from {request.remote_addr} - "
        f"client_id={client_id}, scope={scope}, redirect_uri={redirect_uri}"
    )

    # Generate authorization code
    auth_code = f"demo_auth_code_{uuid.uuid4().hex[:16]}"
    _authorization_codes[auth_code] = {
        "client_id": client_id,
        "scope": scope,
        "redirect_uri": redirect_uri,
        "created_at": datetime.utcnow().isoformat()
    }

    # Return HTML consent screen (simulated phishing page)
    html = f"""<!DOCTYPE html>
<html>
<head><title>Authorize Application</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 500px; margin: 40px auto; padding: 20px; }}
.app-name {{ font-size: 24px; font-weight: bold; color: #d73a49; }}
.scope {{ background: #fff3cd; padding: 8px 12px; margin: 4px 0; border-radius: 4px; border-left: 4px solid #ffc107; }}
.scope.dangerous {{ background: #f8d7da; border-left-color: #dc3545; }}
.btn {{ display: inline-block; padding: 10px 20px; margin: 8px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; }}
.btn-approve {{ background: #28a745; color: white; }}
.btn-deny {{ background: #6c757d; color: white; }}
.warning {{ color: #856404; background: #fff3cd; padding: 12px; border-radius: 4px; margin: 16px 0; }}
</style></head>
<body>
<h2>Authorize Application</h2>
<p><span class="app-name">{client_id}</span> wants to access your account</p>

<h3>Requested Permissions:</h3>
<div class="scope dangerous">admin:org - Full control of orgs and teams</div>
<div class="scope dangerous">repo - Full control of private repositories</div>
<div class="scope">user:email - Access email addresses (read-only)</div>

<div class="warning">
This application is requesting broad permissions including admin access to your organization.
</div>

<p>Authorizing will redirect to: <code>{redirect_uri}</code></p>

<div>
<a class="btn btn-approve" href="{redirect_uri}?code={auth_code}&state={state}">Authorize</a>
<a class="btn btn-deny" href="{redirect_uri}?error=access_denied&state={state}">Deny</a>
</div>

<hr>
<p><small>Mock OAuth Provider - NHI Security Testbed (NDC Security 2026)</small></p>
<p><small>This is a simulated consent phishing page for security training.</small></p>
</body></html>"""

    return Response(html, mimetype="text/html")


# ============================================================
# Token Endpoints - Credential Theft
# ============================================================

@app.route("/oauth/token", methods=["POST"])
def token_exchange():
    """
    OAuth2 Token Exchange Endpoint

    Supports three grant types:
    - authorization_code: Exchange auth code for token (consent phishing result)
    - client_credentials: Machine-to-machine token (NHI abuse)
    - refresh_token: Token renewal (refresh token theft)
    """
    log_access("/oauth/token", request.remote_addr)

    grant_type = request.form.get("grant_type", "")
    client_id = request.form.get("client_id", OAUTH_CLIENT_ID)
    client_secret = request.form.get("client_secret", "")
    scope = request.form.get("scope", "openid profile email")

    now = datetime.utcnow()
    token_id = str(uuid.uuid4())

    if grant_type == "authorization_code":
        code = request.form.get("code", "")
        code_data = _authorization_codes.pop(code, None)

        if not code_data:
            logger.warning(f"[ATTACK] Invalid authorization code from {request.remote_addr}")
            return jsonify({"error": "invalid_grant", "error_description": "Invalid authorization code"}), 400

        scope = code_data.get("scope", scope)
        logger.warning(
            f"[CRITICAL ATTACK] Authorization code exchanged for token from {request.remote_addr} - "
            f"client_id={client_id}, scope={scope}"
        )

    elif grant_type == "client_credentials":
        logger.warning(
            f"[CRITICAL ATTACK] Client credentials token issued from {request.remote_addr} - "
            f"client_id={client_id}, scope={scope}"
        )

    elif grant_type == "refresh_token":
        refresh_token = request.form.get("refresh_token", "")
        if refresh_token not in _refresh_tokens:
            logger.warning(f"[ATTACK] Invalid refresh token from {request.remote_addr}")
            return jsonify({"error": "invalid_grant", "error_description": "Invalid refresh token"}), 400

        scope = _refresh_tokens[refresh_token].get("scope", scope)
        logger.warning(
            f"[CRITICAL ATTACK] Refresh token exchanged from {request.remote_addr} - "
            f"client_id={client_id}, scope={scope}"
        )
    else:
        return jsonify({"error": "unsupported_grant_type"}), 400

    # Build JWT claims
    claims = {
        "iss": OAUTH_ISSUER,
        "sub": client_id,
        "aud": OAUTH_ISSUER,
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "jti": token_id,
        "scope": scope,
        "client_id": client_id
    }

    access_token = _sign_token(claims)

    # Generate refresh token
    new_refresh_token = f"demo_refresh_{uuid.uuid4().hex}"
    _refresh_tokens[new_refresh_token] = {"scope": scope, "client_id": client_id}

    # Build ID token for OIDC flows
    id_claims = {
        **claims,
        "name": "Demo User",
        "email": "demo@example.com",
        "email_verified": True
    }
    id_token = _sign_token(id_claims)

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": new_refresh_token,
        "scope": scope,
        "id_token": id_token
    })


@app.route("/oauth/token/introspect", methods=["POST"])
def token_introspect():
    """
    Token Introspection Endpoint

    Used to inspect stolen tokens and understand their permissions.
    """
    log_access("/oauth/token/introspect", request.remote_addr)

    token = request.form.get("token", "")
    logger.warning(f"[CRITICAL ATTACK] Token introspection from {request.remote_addr}")

    if not token:
        return jsonify({"active": False})

    # Attempt to decode the token
    try:
        decoded = jwt.decode(token, _public_key, algorithms=["RS256"], audience=OAUTH_ISSUER)
        return jsonify({
            "active": True,
            "scope": decoded.get("scope", ""),
            "client_id": decoded.get("client_id", ""),
            "sub": decoded.get("sub", ""),
            "exp": decoded.get("exp", 0),
            "iat": decoded.get("iat", 0),
            "iss": decoded.get("iss", ""),
            "token_type": "Bearer"
        })
    except jwt.ExpiredSignatureError:
        return jsonify({"active": False, "error": "token_expired"})
    except jwt.InvalidTokenError:
        return jsonify({"active": False, "error": "invalid_token"})


# ============================================================
# UserInfo Endpoint - Identity Enumeration
# ============================================================

@app.route("/userinfo")
def userinfo():
    """
    OIDC UserInfo Endpoint

    Returns identity information for the authenticated user.
    Attackers use this to enumerate identity after token theft.
    """
    log_access("/userinfo", request.remote_addr)
    logger.warning(f"[ATTACK] UserInfo accessed from {request.remote_addr} - identity enumeration")

    auth = request.headers.get("Authorization", "")
    token_info = {"sub": "unknown"}

    if auth.startswith("Bearer "):
        try:
            token_info = jwt.decode(
                auth[7:], _public_key, algorithms=["RS256"], audience=OAUTH_ISSUER
            )
        except jwt.InvalidTokenError:
            pass

    return jsonify({
        "sub": token_info.get("sub", "demo-user"),
        "name": "Demo User",
        "email": "demo@example.com",
        "email_verified": True,
        "preferred_username": "demo-user",
        "groups": ["org-admins", "developers", "cloud-ops"],
        "org_roles": {
            "demo-org": "admin",
            "production-org": "member"
        },
        "_demo_note": "This user has admin access to the organization"
    })


# ============================================================
# Health Check
# ============================================================

@app.route("/")
def index():
    """Root endpoint"""
    return jsonify({
        "service": "Mock OAuth2/OIDC Provider",
        "version": "1.0.0",
        "description": "NDC Security 2026 - NHI Testbed",
        "endpoints": {
            "/": "This page",
            "/health": "Health check",
            "/.well-known/openid-configuration": "OIDC discovery",
            "/.well-known/jwks.json": "JWKS public keys",
            "/authorize": "Authorization (consent screen)",
            "/oauth/token": "Token exchange",
            "/oauth/token/introspect": "Token introspection",
            "/userinfo": "OIDC userinfo"
        }
    })


@app.route("/health")
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "mock-oauth"})


if __name__ == "__main__":
    print("=" * 60)
    print("Mock OAuth2/OIDC Provider")
    print("NDC Security 2026 - NHI Security Testbed")
    print("=" * 60)
    print("")
    print("Simulates OAuth2 authorization for demonstrating")
    print("consent phishing and token theft attacks.")
    print("")
    print(f"Listening on port {OAUTH_PORT}")
    print(f"Issuer: {OAUTH_ISSUER}")
    print(f"Client ID: {OAUTH_CLIENT_ID}")
    print("")
    print("CRITICAL ENDPOINTS:")
    print(f"  http://localhost:{OAUTH_PORT}/authorize")
    print(f"  http://localhost:{OAUTH_PORT}/oauth/token")
    print(f"  http://localhost:{OAUTH_PORT}/.well-known/openid-configuration")
    print("=" * 60)

    app.run(host="0.0.0.0", port=OAUTH_PORT, debug=False)
