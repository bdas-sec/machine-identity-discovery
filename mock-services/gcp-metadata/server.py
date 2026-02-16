#!/usr/bin/env python3
"""
Mock GCP Metadata Service + Workload Identity Federation
NDC Security 2026 - NHI Security Testbed

Simulates GCP Compute Engine metadata service and
Workload Identity Federation token exchange.

Endpoints:
- /computeMetadata/v1/                                  - Metadata root
- /computeMetadata/v1/project/project-id                - Project ID
- /computeMetadata/v1/instance/service-accounts/        - Service accounts
- /computeMetadata/v1/instance/service-accounts/default/token    - Access token
- /computeMetadata/v1/instance/service-accounts/default/identity - ID token
- /v1/token                                              - STS token exchange (WIF)
- /v1/projects/-/serviceAccounts/<sa>:generateAccessToken - SA impersonation

All credentials returned are FAKE and for demonstration only.
"""

import os
import json
import uuid
import base64
import logging
import functools
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock-gcp-metadata")

# Configuration from environment
GCP_PORT = int(os.environ.get("GCP_PORT", 1339))
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "demo-project-12345")
GCP_PROJECT_NUMBER = os.environ.get("GCP_PROJECT_NUMBER", "123456789012")
GCP_SERVICE_ACCOUNT = os.environ.get(
    "GCP_SERVICE_ACCOUNT",
    "demo-compute@demo-project-12345.iam.gserviceaccount.com"
)
GCP_ACCESS_TOKEN = os.environ.get("GCP_ACCESS_TOKEN", "ya29.DEMO_GCP_ACCESS_TOKEN_FOR_TESTING")
GCP_ZONE = os.environ.get("GCP_ZONE", "us-central1-a")
GCP_INSTANCE_NAME = os.environ.get("GCP_INSTANCE_NAME", "demo-instance-001")


def log_access(endpoint: str, source_ip: str):
    """Log all GCP metadata access for monitoring"""
    logger.warning(f"GCP-METADATA ACCESS: {source_ip} -> {endpoint}")


def require_metadata_flavor(f):
    """
    Decorator to enforce Metadata-Flavor: Google header.
    GCP metadata service returns 403 Forbidden without this header.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get("Metadata-Flavor") != "Google":
            log_access(request.path, request.remote_addr)
            logger.warning(
                f"[ATTACK] Missing Metadata-Flavor header from {request.remote_addr} - "
                f"possible non-GCP access to {request.path}"
            )
            return Response(
                json.dumps({
                    "error": {
                        "code": 403,
                        "message": "Missing required header: Metadata-Flavor: Google",
                        "status": "PERMISSION_DENIED"
                    }
                }),
                status=403,
                mimetype="application/json"
            )
        return f(*args, **kwargs)
    return decorated


# ============================================================
# GCP Compute Engine Metadata Endpoints
# ============================================================

@app.route("/computeMetadata/v1/")
@app.route("/computeMetadata/v1")
@require_metadata_flavor
def metadata_root():
    """GCP metadata root - lists available metadata categories"""
    log_access("/computeMetadata/v1/", request.remote_addr)
    return "instance/\nproject/\n"


@app.route("/computeMetadata/v1/project/project-id")
@require_metadata_flavor
def project_id():
    """Return GCP project ID"""
    log_access("/computeMetadata/v1/project/project-id", request.remote_addr)
    return GCP_PROJECT_ID


@app.route("/computeMetadata/v1/project/numeric-project-id")
@require_metadata_flavor
def numeric_project_id():
    """Return GCP numeric project ID"""
    log_access("/computeMetadata/v1/project/numeric-project-id", request.remote_addr)
    return GCP_PROJECT_NUMBER


@app.route("/computeMetadata/v1/project/attributes/")
@app.route("/computeMetadata/v1/project/attributes")
@require_metadata_flavor
def project_attributes():
    """Return project attributes listing"""
    log_access("/computeMetadata/v1/project/attributes/", request.remote_addr)
    return "ssh-keys\nenable-oslogin\n"


@app.route("/computeMetadata/v1/instance/name")
@require_metadata_flavor
def instance_name():
    """Return instance name"""
    log_access("/computeMetadata/v1/instance/name", request.remote_addr)
    return GCP_INSTANCE_NAME


@app.route("/computeMetadata/v1/instance/zone")
@require_metadata_flavor
def instance_zone():
    """Return instance zone"""
    log_access("/computeMetadata/v1/instance/zone", request.remote_addr)
    return f"projects/{GCP_PROJECT_NUMBER}/zones/{GCP_ZONE}"


@app.route("/computeMetadata/v1/instance/id")
@require_metadata_flavor
def instance_id():
    """Return instance ID"""
    log_access("/computeMetadata/v1/instance/id", request.remote_addr)
    return "1234567890123456789"


@app.route("/computeMetadata/v1/instance/machine-type")
@require_metadata_flavor
def machine_type():
    """Return machine type"""
    log_access("/computeMetadata/v1/instance/machine-type", request.remote_addr)
    return f"projects/{GCP_PROJECT_NUMBER}/machineTypes/e2-medium"


# ============================================================
# Service Account Endpoints - THE CRITICAL ATTACK TARGET
# ============================================================

@app.route("/computeMetadata/v1/instance/service-accounts/")
@app.route("/computeMetadata/v1/instance/service-accounts")
@require_metadata_flavor
def service_accounts_list():
    """
    List service accounts - RECONNAISSANCE STEP
    Attackers enumerate available service accounts
    """
    log_access("/computeMetadata/v1/instance/service-accounts/", request.remote_addr)
    logger.warning(f"[ATTACK] GCP service account enumeration from {request.remote_addr}")

    return f"default/\n{GCP_SERVICE_ACCOUNT}/\n"


@app.route("/computeMetadata/v1/instance/service-accounts/default/")
@app.route("/computeMetadata/v1/instance/service-accounts/default")
@require_metadata_flavor
def service_account_default():
    """Service account default info"""
    log_access("/computeMetadata/v1/instance/service-accounts/default/", request.remote_addr)
    return jsonify({
        "aliases": ["default"],
        "email": GCP_SERVICE_ACCOUNT,
        "scopes": [
            "https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/compute",
            "https://www.googleapis.com/auth/devstorage.read_write",
            "https://www.googleapis.com/auth/logging.write",
            "https://www.googleapis.com/auth/monitoring.write"
        ]
    })


@app.route("/computeMetadata/v1/instance/service-accounts/default/token")
@require_metadata_flavor
def service_account_token():
    """
    CREDENTIAL THEFT ENDPOINT - GCP Access Token
    This returns an OAuth2 access token for the default service account.

    In a real attack:
    1. Attacker exploits SSRF vulnerability
    2. SSRF targets this endpoint with Metadata-Flavor: Google header
    3. Access token is exfiltrated
    4. Attacker uses token to access GCP APIs (Storage, Compute, IAM, etc.)
    """
    log_access("/computeMetadata/v1/instance/service-accounts/default/token", request.remote_addr)
    logger.warning(
        f"[CRITICAL ATTACK] GCP service account token theft from {request.remote_addr} - "
        f"SA: {GCP_SERVICE_ACCOUNT}"
    )

    return jsonify({
        "access_token": GCP_ACCESS_TOKEN,
        "expires_in": 3599,
        "token_type": "Bearer"
    })


@app.route("/computeMetadata/v1/instance/service-accounts/default/identity")
@require_metadata_flavor
def service_account_identity():
    """
    GCP Identity Token Endpoint
    Returns an OIDC identity token for the service account.
    Used for authenticating to other services.
    """
    log_access("/computeMetadata/v1/instance/service-accounts/default/identity", request.remote_addr)

    audience = request.args.get("audience", "https://example.com")
    logger.warning(
        f"[CRITICAL ATTACK] GCP identity token request from {request.remote_addr} - "
        f"audience={audience}"
    )

    # Build a fake identity token (base64-encoded JWT structure)
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT", "kid": "demo-gcp-key-1"}).encode()
    ).rstrip(b"=").decode()

    now = int(datetime.utcnow().timestamp())
    payload = base64.urlsafe_b64encode(json.dumps({
        "iss": "https://accounts.google.com",
        "aud": audience,
        "azp": GCP_SERVICE_ACCOUNT,
        "sub": "100000000000000000001",
        "email": GCP_SERVICE_ACCOUNT,
        "email_verified": True,
        "iat": now,
        "exp": now + 3600
    }).encode()).rstrip(b"=").decode()

    signature = "DEMO_GCP_SIGNATURE_NOT_VALID"
    return f"{header}.{payload}.{signature}"


# ============================================================
# Workload Identity Federation (WIF) - STS Token Exchange
# ============================================================

@app.route("/v1/token", methods=["POST"])
def sts_token_exchange():
    """
    GCP Security Token Service - Workload Identity Federation

    Exchanges an external identity token (e.g., GitHub OIDC, AWS STS)
    for a GCP federated access token.

    In a real attack:
    1. Attacker steals CI/CD OIDC token (e.g., from GitHub Actions)
    2. Exchanges it via WIF for GCP access
    3. Uses GCP token to access cloud resources
    """
    log_access("/v1/token", request.remote_addr)

    data = request.get_json(silent=True) or {}
    grant_type = data.get("grant_type", request.form.get("grant_type", ""))
    subject_token = data.get("subject_token", request.form.get("subject_token", ""))
    subject_token_type = data.get("subject_token_type", request.form.get("subject_token_type", ""))
    requested_scope = data.get("scope", request.form.get(
        "scope", "https://www.googleapis.com/auth/cloud-platform"
    ))

    logger.warning(
        f"[CRITICAL ATTACK] WIF token exchange from {request.remote_addr} - "
        f"grant_type={grant_type}, token_type={subject_token_type}"
    )

    if grant_type != "urn:ietf:params:oauth:grant-type:token-exchange":
        return jsonify({
            "error": "invalid_request",
            "error_description": "Unsupported grant_type"
        }), 400

    if not subject_token:
        return jsonify({
            "error": "invalid_request",
            "error_description": "subject_token is required"
        }), 400

    # Return federated access token
    federated_token = f"ya29.c.DEMO_FEDERATED_{uuid.uuid4().hex[:16]}"
    return jsonify({
        "access_token": federated_token,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": requested_scope
    })


# ============================================================
# Service Account Impersonation
# ============================================================

@app.route("/v1/projects/-/serviceAccounts/<path:sa_email>:generateAccessToken", methods=["POST"])
def generate_access_token(sa_email: str):
    """
    Service Account Impersonation - generateAccessToken

    Generates an access token for a target service account.
    Used in privilege escalation: attacker with iam.serviceAccounts.getAccessToken
    permission can impersonate any service account.

    In a real attack:
    1. Attacker compromises low-privilege service account
    2. Discovers it has iam.serviceAccounts.getAccessToken on a high-privilege SA
    3. Calls this endpoint to get a token for the high-privilege SA
    """
    log_access(f"/v1/projects/-/serviceAccounts/{sa_email}:generateAccessToken", request.remote_addr)
    logger.warning(
        f"[CRITICAL ATTACK] Service account impersonation from {request.remote_addr} - "
        f"target SA: {sa_email}"
    )

    data = request.get_json(silent=True) or {}
    requested_scope = data.get("scope", ["https://www.googleapis.com/auth/cloud-platform"])
    lifetime = data.get("lifetime", "3600s")

    impersonated_token = f"ya29.c.DEMO_IMPERSONATED_{uuid.uuid4().hex[:16]}"
    expire_time = (datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    return jsonify({
        "accessToken": impersonated_token,
        "expireTime": expire_time
    })


# ============================================================
# Health Check
# ============================================================

@app.route("/")
def index():
    """Root endpoint"""
    log_access("/", request.remote_addr)
    return jsonify({
        "service": "Mock GCP Metadata Service",
        "version": "1.0.0",
        "description": "NDC Security 2026 - NHI Testbed",
        "endpoints": {
            "/": "This page",
            "/health": "Health check",
            "/computeMetadata/v1/": "GCP metadata root",
            "/computeMetadata/v1/instance/service-accounts/default/token": "SA access token",
            "/computeMetadata/v1/instance/service-accounts/default/identity": "SA identity token",
            "/v1/token": "STS token exchange (WIF)",
            "/v1/projects/-/serviceAccounts/<sa>:generateAccessToken": "SA impersonation"
        },
        "note": "Most endpoints require Metadata-Flavor: Google header"
    })


@app.route("/health")
def health():
    """Health check endpoint - no Metadata-Flavor header required"""
    return jsonify({"status": "healthy", "service": "mock-gcp-metadata"})


if __name__ == "__main__":
    print("=" * 60)
    print("Mock GCP Metadata Service + Workload Identity Federation")
    print("NDC Security 2026 - NHI Security Testbed")
    print("=" * 60)
    print("")
    print("Simulates GCP Compute Engine metadata and WIF for")
    print("demonstrating credential theft and identity federation attacks.")
    print("")
    print(f"Listening on port {GCP_PORT}")
    print(f"Project: {GCP_PROJECT_ID} ({GCP_PROJECT_NUMBER})")
    print(f"Service Account: {GCP_SERVICE_ACCOUNT}")
    print("")
    print("CRITICAL ENDPOINTS:")
    print(f"  http://localhost:{GCP_PORT}/computeMetadata/v1/instance/service-accounts/default/token")
    print(f"  http://localhost:{GCP_PORT}/v1/token")
    print(f"  http://localhost:{GCP_PORT}/v1/projects/-/serviceAccounts/<sa>:generateAccessToken")
    print("=" * 60)

    app.run(host="0.0.0.0", port=GCP_PORT, debug=False)
