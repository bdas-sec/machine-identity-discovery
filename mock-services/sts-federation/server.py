#!/usr/bin/env python3
"""
Mock STS Federation Service
NHI Security Testbed

Simulates OAuth/OIDC token exchange, AWS STS, and Azure AD token endpoints
for demonstrating OAuth/OIDC token abuse attack scenarios.

Endpoints:
- POST /v1/token                                    - Generic token exchange
- POST /sts/AssumeRoleWithWebIdentity               - AWS STS simulation
- POST /oauth2/v2.0/token                           - Azure AD token endpoint
- GET  /v1/identity/oidc/.well-known/openid-configuration  - OIDC discovery
- POST /oauth2/v2.0/authorize                       - Consent flow simulation
- GET  /health                                      - Health check

All tokens returned are FAKE and for demonstration only.
"""

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify, Response

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock-sts-federation")

# Configuration
STS_PORT = int(os.environ.get("STS_PORT", 8091))
ISSUER_URL = os.environ.get("ISSUER_URL", "https://mock-sts-federation:8091")

# Track token exchanges for detection
token_exchange_log = []

# High-privilege scopes that trigger alerts
HIGH_PRIVILEGE_SCOPES = {
    "Directory.ReadWrite.All", "Mail.Read", "Mail.ReadWrite",
    "User.Read.All", "User.ReadWrite.All", "Application.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory", "admin:org", "repo",
    "https://management.azure.com/.default",
    "https://graph.microsoft.com/.default",
}


def _log_to_syslog(event_type: str, details: dict):
    """Log token exchange events in a format Wazuh can parse."""
    source_ip = request.remote_addr or "unknown"
    detail_str = json.dumps(details, separators=(",", ":"))
    logger.warning(
        "STS_FEDERATION %s: %s from %s %s",
        event_type, details.get("grant_type", "unknown"), source_ip, detail_str
    )


def _generate_fake_access_token(claims: dict) -> str:
    """Generate a realistic-looking but fake JWT access token."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT", "kid": "mock-key-1"}).encode()
    ).rstrip(b"=").decode()

    payload_data = {
        "iss": ISSUER_URL,
        "sub": claims.get("sub", "mock-subject"),
        "aud": claims.get("aud", "mock-audience"),
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "jti": str(uuid.uuid4()),
    }
    payload_data.update(claims)
    payload = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()
    ).rstrip(b"=").decode()

    # Fake signature (not cryptographically valid)
    sig_input = f"{header}.{payload}".encode()
    sig = base64.urlsafe_b64encode(
        hashlib.sha256(sig_input).digest()
    ).rstrip(b"=").decode()

    return f"{header}.{payload}.{sig}"


def _detect_high_privilege_scopes(scope_str: str) -> list:
    """Check if requested scopes include high-privilege permissions."""
    if not scope_str:
        return []
    requested = set(scope_str.split())
    return sorted(requested & HIGH_PRIVILEGE_SCOPES)


def _detect_audience_mismatch(subject_token: str, requested_audience: str) -> bool:
    """Detect if the subject token audience differs from the requested audience."""
    if not subject_token or not requested_audience:
        return False
    try:
        # Try to decode the JWT payload
        parts = subject_token.split(".")
        if len(parts) >= 2:
            padding = 4 - len(parts[1]) % 4
            payload = json.loads(
                base64.urlsafe_b64decode(parts[1] + "=" * padding)
            )
            token_aud = payload.get("aud", "")
            if token_aud and token_aud != requested_audience:
                return True
    except Exception:
        pass
    return False


# ============================================================
# OIDC Discovery Endpoint
# ============================================================

@app.route("/v1/identity/oidc/.well-known/openid-configuration", methods=["GET"])
def oidc_discovery():
    """OIDC Discovery document."""
    _log_to_syslog("OIDC_DISCOVERY", {"endpoint": "openid-configuration"})
    return jsonify({
        "issuer": ISSUER_URL,
        "authorization_endpoint": f"{ISSUER_URL}/oauth2/v2.0/authorize",
        "token_endpoint": f"{ISSUER_URL}/v1/token",
        "jwks_uri": f"{ISSUER_URL}/v1/identity/oidc/.well-known/jwks",
        "response_types_supported": ["code", "id_token", "token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post", "private_key_jwt"
        ],
        "grant_types_supported": [
            "authorization_code", "client_credentials", "refresh_token",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
    })


# ============================================================
# Generic Token Exchange Endpoint
# ============================================================

@app.route("/v1/token", methods=["POST"])
def token_exchange():
    """Generic token exchange endpoint.

    Handles JWT bearer, token exchange, refresh token, and client credentials.
    """
    source_ip = request.remote_addr
    content_type = request.content_type or ""

    if "json" in content_type:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict()

    grant_type = data.get("grant_type", "unknown")
    client_id = data.get("client_id", "unknown")
    audience = data.get("audience", data.get("aud", ""))
    scope = data.get("scope", "")
    subject_token = data.get("subject_token", data.get("assertion", ""))

    event = {
        "grant_type": grant_type,
        "client_id": client_id,
        "audience": audience,
        "scope": scope,
        "source_ip": source_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Detect audience mismatch
    if _detect_audience_mismatch(subject_token, audience):
        logger.warning(
            "[ATTACK] OIDC audience mismatch: token audience differs from "
            "requested audience '%s' from %s",
            audience, source_ip,
        )
        _log_to_syslog("AUDIENCE_MISMATCH", {
            **event,
            "attack": "audience_confusion",
            "requested_audience": audience,
        })

    # Detect GitHub Actions OIDC federation
    if subject_token and ("actions.githubusercontent.com" in subject_token
                          or "repo:" in subject_token):
        logger.warning(
            "[ATTACK] GitHub Actions OIDC federation detected: "
            "CI/CD to cloud pivot from %s",
            source_ip,
        )
        _log_to_syslog("GITHUB_ACTIONS_OIDC", {
            **event,
            "attack": "github_actions_oidc_federation",
        })

    # Detect high-privilege scope requests
    high_priv = _detect_high_privilege_scopes(scope)
    if high_priv:
        logger.warning(
            "[ATTACK] High-privilege scope request: %s from %s",
            high_priv, source_ip,
        )

    # Detect refresh token usage
    if grant_type == "refresh_token":
        logger.warning(
            "[ATTACK] Refresh token exchange from %s client_id=%s",
            source_ip, client_id,
        )
        _log_to_syslog("REFRESH_TOKEN_USE", {
            **event,
            "attack": "refresh_token_abuse",
        })

    _log_to_syslog("TOKEN_EXCHANGE", event)

    # Generate response
    access_token = _generate_fake_access_token({
        "sub": client_id,
        "aud": audience or "mock-audience",
        "scope": scope,
    })

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": scope or "openid profile",
        "refresh_token": f"0.mock-refresh-{uuid.uuid4().hex[:16]}",
    })


# ============================================================
# AWS STS AssumeRoleWithWebIdentity
# ============================================================

@app.route("/sts/AssumeRoleWithWebIdentity", methods=["POST"])
def assume_role_with_web_identity():
    """AWS STS AssumeRoleWithWebIdentity simulation."""
    source_ip = request.remote_addr
    data = request.form.to_dict()

    role_arn = data.get("RoleArn", "arn:aws:iam::123456789012:role/unknown")
    session_name = data.get("RoleSessionName", "unknown-session")
    web_identity_token = data.get("WebIdentityToken", "")

    event = {
        "grant_type": "AssumeRoleWithWebIdentity",
        "role_arn": role_arn,
        "session_name": session_name,
        "source_ip": source_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    logger.warning(
        "[ATTACK] STS AssumeRoleWithWebIdentity: role=%s session=%s from %s",
        role_arn, session_name, source_ip,
    )
    _log_to_syslog("STS_ASSUME_ROLE", event)

    # Detect GitHub Actions OIDC in the web identity token
    if web_identity_token and ("actions.githubusercontent" in web_identity_token
                               or "repo:" in web_identity_token):
        logger.warning(
            "[CRITICAL ATTACK] GitHub Actions OIDC to AWS STS federation "
            "from %s role=%s",
            source_ip, role_arn,
        )
        _log_to_syslog("GITHUB_OIDC_TO_AWS", {
            **event,
            "attack": "github_actions_oidc_to_aws",
        })

    # Generate fake AWS STS response
    expiration = datetime.now(timezone.utc) + timedelta(hours=1)
    return jsonify({
        "AssumeRoleWithWebIdentityResponse": {
            "AssumeRoleWithWebIdentityResult": {
                "Credentials": {
                    "AccessKeyId": f"ASIA{'DEMO' + uuid.uuid4().hex[:12].upper()}",
                    "SecretAccessKey": f"wJalrXUtnFEMI/DEMO/STOLEN/{uuid.uuid4().hex[:16]}",
                    "SessionToken": f"FwoGZXIvYXdzEBYaDEMO{uuid.uuid4().hex[:32]}",
                    "Expiration": expiration.isoformat(),
                },
                "SubjectFromWebIdentityToken": session_name,
                "AssumedRoleUser": {
                    "AssumedRoleId": f"AROA{'DEMO' + uuid.uuid4().hex[:12].upper()}:{session_name}",
                    "Arn": role_arn.replace(":role/", ":assumed-role/") + f"/{session_name}",
                },
            }
        }
    })


# ============================================================
# Azure AD Token Endpoint
# ============================================================

@app.route("/oauth2/v2.0/token", methods=["POST"])
def azure_ad_token():
    """Azure AD token endpoint simulation."""
    source_ip = request.remote_addr
    data = request.form.to_dict()

    grant_type = data.get("grant_type", "unknown")
    client_id = data.get("client_id", "unknown")
    scope = data.get("scope", "")
    tenant = data.get("tenant", "common")
    action = data.get("action", "")

    event = {
        "grant_type": grant_type,
        "client_id": client_id,
        "scope": scope,
        "tenant": tenant,
        "source_ip": source_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Detect high-privilege consent requests
    high_priv = _detect_high_privilege_scopes(scope)
    if high_priv:
        logger.warning(
            "[ATTACK] Azure AD high-privilege consent request: "
            "client_id=%s scopes=%s from %s",
            client_id, high_priv, source_ip,
        )
        _log_to_syslog("AZURE_HIGH_PRIV_CONSENT", {
            **event,
            "attack": "consent_escalation",
            "high_privilege_scopes": high_priv,
        })

    # Detect admin consent
    if "admin_consent" in scope or "admin_consent" in data.get("prompt", ""):
        logger.warning(
            "[CRITICAL ATTACK] Azure AD admin consent granted: "
            "client_id=%s from %s",
            client_id, source_ip,
        )
        _log_to_syslog("AZURE_ADMIN_CONSENT", {
            **event,
            "attack": "admin_consent_abuse",
        })

    # Detect credential creation during rotation (addPassword)
    if action == "addPassword" or "addPassword" in scope:
        logger.warning(
            "[ATTACK] Service principal credential creation during "
            "rotation: client_id=%s from %s",
            client_id, source_ip,
        )
        _log_to_syslog("SP_CREDENTIAL_ROTATION", {
            **event,
            "attack": "sp_rotation_race",
        })

    # Detect refresh token usage
    if grant_type == "refresh_token":
        logger.warning(
            "[ATTACK] Azure AD refresh token exchange from %s "
            "client_id=%s",
            source_ip, client_id,
        )
        _log_to_syslog("AZURE_REFRESH_TOKEN", {
            **event,
            "attack": "refresh_token_abuse",
        })

    _log_to_syslog("AZURE_TOKEN_REQUEST", event)

    access_token = _generate_fake_access_token({
        "sub": client_id,
        "aud": scope.split()[0] if scope else "https://graph.microsoft.com",
        "tid": tenant,
        "roles": high_priv if high_priv else ["User.Read"],
        "scp": scope,
    })

    response = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": scope or "User.Read",
        "ext_expires_in": 3600,
    }

    if grant_type in ("authorization_code", "refresh_token"):
        response["refresh_token"] = f"0.ARoA-mock-{uuid.uuid4().hex[:24]}"

    return jsonify(response)


# ============================================================
# Azure AD Consent Flow
# ============================================================

@app.route("/oauth2/v2.0/authorize", methods=["POST", "GET"])
def consent_flow():
    """Azure AD consent flow simulation."""
    source_ip = request.remote_addr

    if request.method == "GET":
        data = request.args.to_dict()
    else:
        content_type = request.content_type or ""
        if "json" in content_type:
            data = request.get_json(silent=True) or {}
        else:
            data = request.form.to_dict()

    client_id = data.get("client_id", "unknown")
    scope = data.get("scope", "")
    redirect_uri = data.get("redirect_uri", "")
    prompt = data.get("prompt", "")

    event = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "scope": scope,
        "redirect_uri": redirect_uri,
        "prompt": prompt,
        "source_ip": source_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Detect admin consent phishing
    if prompt == "admin_consent":
        logger.warning(
            "[CRITICAL ATTACK] Admin consent request: client_id=%s "
            "scope=%s redirect=%s from %s",
            client_id, scope, redirect_uri, source_ip,
        )
        _log_to_syslog("ADMIN_CONSENT_REQUEST", {
            **event,
            "attack": "consent_phishing",
        })

    # Detect high-privilege scope requests
    high_priv = _detect_high_privilege_scopes(scope)
    if high_priv:
        logger.warning(
            "[ATTACK] Consent request with high-privilege scopes: %s "
            "from %s",
            high_priv, source_ip,
        )
        _log_to_syslog("HIGH_PRIV_CONSENT_REQUEST", {
            **event,
            "attack": "excessive_consent_request",
            "high_privilege_scopes": high_priv,
        })

    # Detect suspicious redirect URI
    if redirect_uri and "attacker" in redirect_uri.lower():
        logger.warning(
            "[ATTACK] Suspicious redirect URI in consent flow: %s "
            "from %s",
            redirect_uri, source_ip,
        )

    _log_to_syslog("CONSENT_FLOW", event)

    return jsonify({
        "authorization_code": f"mock-authz-code-{uuid.uuid4().hex[:16]}",
        "state": data.get("state", ""),
        "client_id": client_id,
        "consent_granted": True,
        "scopes_granted": scope,
    })


# ============================================================
# Health Check
# ============================================================

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    _log_to_syslog("HEALTH_CHECK", {"status": "healthy"})
    return jsonify({
        "status": "healthy",
        "service": "mock-sts-federation",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoints": [
            "/v1/token",
            "/sts/AssumeRoleWithWebIdentity",
            "/oauth2/v2.0/token",
            "/oauth2/v2.0/authorize",
            "/v1/identity/oidc/.well-known/openid-configuration",
            "/health",
        ],
    })


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    logger.info("Mock STS Federation Service starting on port %d", STS_PORT)
    app.run(host="0.0.0.0", port=STS_PORT, debug=False)
