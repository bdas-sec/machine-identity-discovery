#!/usr/bin/env python3
"""
Mock Instance Metadata Service (IMDS)
NDC Security 2026 - NHI Security Testbed

Simulates AWS EC2 Instance Metadata Service for demonstrating
credential theft attacks (SSRF to IMDS).

Endpoints:
- /latest/meta-data/              - Metadata root
- /latest/meta-data/instance-id   - Instance ID
- /latest/meta-data/iam/security-credentials/  - IAM role list
- /latest/meta-data/iam/security-credentials/<role>  - Role credentials
- /latest/api/token               - IMDSv2 token endpoint

All credentials returned are FAKE and for demonstration only.
"""

import os
import json
import uuid
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock-imds")

# Configuration from environment
IMDS_PORT = int(os.environ.get("IMDS_PORT", 1338))
MOCK_ACCESS_KEY_ID = os.environ.get("MOCK_ACCESS_KEY_ID", "ASIADEMOTESTBED00001")
MOCK_SECRET_ACCESS_KEY = os.environ.get("MOCK_SECRET_ACCESS_KEY", "wJalrXUtnFEMI_DEMO_IMDS_STOLEN_KEY")
MOCK_SESSION_TOKEN = os.environ.get("MOCK_SESSION_TOKEN", "FwoGZXIvYXdzEBYaDEMOTOKENFORTESTING...")
MOCK_ROLE_NAME = os.environ.get("MOCK_ROLE_NAME", "demo-ec2-instance-role")

# IMDSv2 tokens storage
imdsv2_tokens = {}


def log_access(endpoint: str, source_ip: str):
    """Log all IMDS access for monitoring"""
    logger.warning(f"IMDS ACCESS: {source_ip} -> {endpoint}")


# ============================================================
# AWS IMDS v1 Endpoints (no token required - less secure)
# ============================================================

@app.route("/")
def root():
    """IMDS root"""
    log_access("/", request.remote_addr)
    return "Mock IMDS Service - NDC Security 2026 Demo\n"


@app.route("/latest/")
def latest():
    """IMDS latest root"""
    log_access("/latest/", request.remote_addr)
    return "dynamic\nmeta-data\nuser-data\n"


@app.route("/latest/meta-data/")
@app.route("/latest/meta-data")
def meta_data_root():
    """Metadata root - lists available metadata"""
    log_access("/latest/meta-data/", request.remote_addr)
    return """ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hostname
iam/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/
"""


@app.route("/latest/meta-data/instance-id")
def instance_id():
    """Return mock instance ID"""
    log_access("/latest/meta-data/instance-id", request.remote_addr)
    return "i-0abc123def456789demo"


@app.route("/latest/meta-data/instance-type")
def instance_type():
    """Return mock instance type"""
    log_access("/latest/meta-data/instance-type", request.remote_addr)
    return "t3.medium"


@app.route("/latest/meta-data/ami-id")
def ami_id():
    """Return mock AMI ID"""
    log_access("/latest/meta-data/ami-id", request.remote_addr)
    return "ami-0demo1234567890ab"


@app.route("/latest/meta-data/hostname")
def hostname():
    """Return mock hostname"""
    log_access("/latest/meta-data/hostname", request.remote_addr)
    return "ip-172-41-0-10.ec2.internal"


@app.route("/latest/meta-data/local-ipv4")
def local_ipv4():
    """Return mock local IP"""
    log_access("/latest/meta-data/local-ipv4", request.remote_addr)
    return "172.41.0.10"


@app.route("/latest/meta-data/public-ipv4")
def public_ipv4():
    """Return mock public IP"""
    log_access("/latest/meta-data/public-ipv4", request.remote_addr)
    return "203.0.113.42"


@app.route("/latest/meta-data/placement/availability-zone")
def availability_zone():
    """Return mock AZ"""
    log_access("/latest/meta-data/placement/availability-zone", request.remote_addr)
    return "us-east-1a"


@app.route("/latest/meta-data/placement/region")
def region():
    """Return mock region"""
    log_access("/latest/meta-data/placement/region", request.remote_addr)
    return "us-east-1"


# ============================================================
# IAM Role Credentials - THE CRITICAL ATTACK TARGET
# ============================================================

@app.route("/latest/meta-data/iam/")
@app.route("/latest/meta-data/iam")
def iam_root():
    """IAM metadata root"""
    log_access("/latest/meta-data/iam/", request.remote_addr)
    return "info\nsecurity-credentials/\n"


@app.route("/latest/meta-data/iam/info")
def iam_info():
    """IAM info"""
    log_access("/latest/meta-data/iam/info", request.remote_addr)
    return json.dumps({
        "Code": "Success",
        "LastUpdated": datetime.utcnow().isoformat() + "Z",
        "InstanceProfileArn": f"arn:aws:iam::123456789012:instance-profile/{MOCK_ROLE_NAME}",
        "InstanceProfileId": "AIPADEMOINSTANCEPROFILE"
    })


@app.route("/latest/meta-data/iam/security-credentials/")
@app.route("/latest/meta-data/iam/security-credentials")
def iam_security_credentials_list():
    """
    List available IAM roles - RECONNAISSANCE STEP
    Attackers first call this to discover role names
    """
    log_access("/latest/meta-data/iam/security-credentials/", request.remote_addr)
    logger.warning(f"[ATTACK] IAM role enumeration from {request.remote_addr}")
    return MOCK_ROLE_NAME + "\n"


@app.route("/latest/meta-data/iam/security-credentials/<role_name>")
def iam_security_credentials(role_name: str):
    """
    CREDENTIAL THEFT ENDPOINT
    This returns temporary IAM credentials - the primary attack target

    In a real attack:
    1. Attacker exploits SSRF vulnerability
    2. SSRF targets this endpoint
    3. Credentials are exfiltrated
    4. Attacker uses credentials from their machine
    """
    log_access(f"/latest/meta-data/iam/security-credentials/{role_name}", request.remote_addr)

    logger.warning(f"[CRITICAL ATTACK] IAM credential theft for role '{role_name}' from {request.remote_addr}")

    # Calculate expiration (6 hours from now, like real AWS)
    expiration = datetime.utcnow() + timedelta(hours=6)

    credentials = {
        "Code": "Success",
        "LastUpdated": datetime.utcnow().isoformat() + "Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": MOCK_ACCESS_KEY_ID,
        "SecretAccessKey": MOCK_SECRET_ACCESS_KEY,
        "Token": MOCK_SESSION_TOKEN,
        "Expiration": expiration.isoformat() + "Z"
    }

    return Response(
        json.dumps(credentials, indent=2),
        mimetype="application/json"
    )


# ============================================================
# IMDSv2 Endpoints (token required - more secure)
# ============================================================

@app.route("/latest/api/token", methods=["PUT"])
def imdsv2_token():
    """
    IMDSv2 Token Endpoint
    Requires PUT request with X-aws-ec2-metadata-token-ttl-seconds header
    Returns a session token that must be included in subsequent requests
    """
    log_access("/latest/api/token", request.remote_addr)

    ttl = request.headers.get("X-aws-ec2-metadata-token-ttl-seconds", "21600")

    try:
        ttl_seconds = int(ttl)
        if ttl_seconds < 1 or ttl_seconds > 21600:
            return "Invalid TTL", 400
    except ValueError:
        return "Invalid TTL", 400

    token = str(uuid.uuid4())
    expiration = datetime.utcnow() + timedelta(seconds=ttl_seconds)
    imdsv2_tokens[token] = expiration

    logger.info(f"IMDSv2 token issued: {token[:8]}... (TTL: {ttl_seconds}s)")

    return token


def validate_imdsv2_token():
    """Validate IMDSv2 token if present"""
    token = request.headers.get("X-aws-ec2-metadata-token")
    if token:
        expiration = imdsv2_tokens.get(token)
        if expiration and datetime.utcnow() < expiration:
            return True
        return False
    return None  # No token provided (v1 access)


# ============================================================
# Azure IMDS Endpoints (for multi-cloud demo)
# ============================================================

@app.route("/metadata/instance")
def azure_metadata():
    """Azure IMDS instance endpoint"""
    log_access("/metadata/instance", request.remote_addr)

    # Check for required Metadata header
    if request.headers.get("Metadata") != "true":
        return "Bad Request", 400

    return jsonify({
        "compute": {
            "location": "eastus",
            "name": "demo-vm",
            "vmId": "12345678-1234-1234-1234-123456789012",
            "vmSize": "Standard_D2s_v3"
        }
    })


@app.route("/metadata/identity/oauth2/token")
def azure_token():
    """
    Azure Managed Identity Token Endpoint
    Similar attack vector to AWS IMDS
    """
    log_access("/metadata/identity/oauth2/token", request.remote_addr)

    if request.headers.get("Metadata") != "true":
        return "Bad Request", 400

    logger.warning(f"[CRITICAL ATTACK] Azure managed identity token request from {request.remote_addr}")

    return jsonify({
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkRFTU9UT0tFTiJ9.DEMO.TOKEN",
        "client_id": "12345678-1234-1234-1234-123456789012",
        "expires_in": "86400",
        "expires_on": str(int((datetime.utcnow() + timedelta(days=1)).timestamp())),
        "ext_expires_in": "86400",
        "not_before": str(int(datetime.utcnow().timestamp())),
        "resource": "https://management.azure.com/",
        "token_type": "Bearer"
    })


@app.route("/health")
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "mock-imds"})


if __name__ == "__main__":
    print("=" * 60)
    print("Mock Instance Metadata Service (IMDS)")
    print("NDC Security 2026 - NHI Security Testbed")
    print("=" * 60)
    print("")
    print("This service simulates AWS/Azure IMDS for demonstrating")
    print("credential theft attacks via SSRF.")
    print("")
    print(f"Listening on port {IMDS_PORT}")
    print(f"Mock IAM Role: {MOCK_ROLE_NAME}")
    print(f"Mock Access Key: {MOCK_ACCESS_KEY_ID}")
    print("")
    print("CRITICAL ENDPOINTS:")
    print(f"  http://localhost:{IMDS_PORT}/latest/meta-data/iam/security-credentials/")
    print(f"  http://localhost:{IMDS_PORT}/latest/meta-data/iam/security-credentials/{MOCK_ROLE_NAME}")
    print("=" * 60)

    app.run(host="0.0.0.0", port=IMDS_PORT, debug=False)
