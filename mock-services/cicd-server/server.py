#!/usr/bin/env python3
"""
Mock CI/CD Server
NDC Security 2026 - NHI Security Testbed

Simulates GitHub Actions / GitLab CI API endpoints for demonstrating
CI/CD token theft and pipeline attacks.

All tokens are FAKE and for demonstration only.
"""

import os
import json
import uuid
import base64
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock-cicd")

# Mock tokens (FAKE - demo only)
GITHUB_ACTIONS_TOKEN = os.environ.get("GITHUB_ACTIONS_TOKEN", "ghs_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
GITLAB_CI_TOKEN = os.environ.get("GITLAB_CI_TOKEN", "glcbt-XXXXXXXXXXXXXXXXXXXX")
AZURE_DEVOPS_TOKEN = os.environ.get("AZURE_DEVOPS_TOKEN", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "12345")
GITHUB_APP_PRIVATE_KEY_STUB = os.environ.get("GITHUB_APP_PRIVATE_KEY_STUB", "demo-private-key")


def log_access(endpoint: str, source_ip: str):
    """Log all CI/CD API access"""
    logger.warning(f"CI/CD ACCESS: {source_ip} -> {endpoint}")


@app.route("/")
def index():
    """Root endpoint"""
    return jsonify({
        "service": "Mock CI/CD Server",
        "version": "2.0.0",
        "description": "NDC Security 2026 - NHI Testbed",
        "endpoints": {
            "/": "This page",
            "/health": "Health check",
            "/github/actions/runner/token": "GitHub Actions runner token",
            "/github/repos/<owner>/<repo>/actions/secrets": "GitHub repo secrets",
            "/github/actions/oidc/token": "GitHub OIDC token (workload identity)",
            "/github/app": "GitHub App info (JWT auth)",
            "/github/app/installations": "GitHub App installations",
            "/github/app/installations/<id>/access_tokens": "GitHub App installation token",
            "/github/app/installations/<id>/repositories": "GitHub App repo access",
            "/gitlab/api/v4/job/token": "GitLab CI job token",
            "/gitlab/api/v4/projects/<id>/variables": "GitLab CI variables",
            "/azure/pipelines/token": "Azure DevOps token"
        }
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "mock-cicd"})


# ============================================================
# GitHub Actions Mock Endpoints
# ============================================================

@app.route("/github/actions/runner/token", methods=["POST"])
def github_runner_token():
    """
    GitHub Actions Runner Registration Token
    Used when registering self-hosted runners
    """
    log_access("/github/actions/runner/token", request.remote_addr)
    logger.warning(f"[ATTACK] GitHub runner token requested from {request.remote_addr}")

    return jsonify({
        "token": "AABCDEFGHIJKLMNOPQRSTUVWXYZ234567890DEMO",
        "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z"
    })


@app.route("/github/repos/<owner>/<repo>/actions/secrets", methods=["GET"])
def github_secrets_list(owner: str, repo: str):
    """
    List GitHub Actions secrets (names only, not values)
    """
    log_access(f"/github/repos/{owner}/{repo}/actions/secrets", request.remote_addr)

    return jsonify({
        "total_count": 3,
        "secrets": [
            {"name": "AWS_ACCESS_KEY_ID", "created_at": "2024-01-01T00:00:00Z"},
            {"name": "AWS_SECRET_ACCESS_KEY", "created_at": "2024-01-01T00:00:00Z"},
            {"name": "DEPLOY_TOKEN", "created_at": "2024-01-01T00:00:00Z"}
        ]
    })


@app.route("/github/repos/<owner>/<repo>/actions/runs/<run_id>/logs", methods=["GET"])
def github_workflow_logs(owner: str, repo: str, run_id: str):
    """
    GitHub Actions workflow logs - may contain leaked secrets
    """
    log_access(f"/github/repos/{owner}/{repo}/actions/runs/{run_id}/logs", request.remote_addr)
    logger.warning(f"[ATTACK] Workflow logs requested - may contain secrets")

    # Simulated log with "accidentally" leaked secret
    return """
2024-01-15T10:30:00.000Z Starting deployment...
2024-01-15T10:30:01.000Z Setting up AWS credentials...
2024-01-15T10:30:02.000Z DEBUG: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
2024-01-15T10:30:02.000Z DEBUG: AWS_SECRET_ACCESS_KEY=wJalrXUtn***REDACTED***
2024-01-15T10:30:03.000Z Deploying to production...
2024-01-15T10:30:10.000Z Deployment complete!
"""


# ============================================================
# GitHub App Authentication Mock Endpoints
# ============================================================

@app.route("/github/app", methods=["GET"])
def github_app_info():
    """
    GitHub App Info Endpoint
    Validates JWT Bearer authentication and returns app details.

    In a real attack:
    1. Attacker steals GitHub App private key
    2. Generates JWT signed with the key
    3. Uses JWT to authenticate as the App
    4. Enumerates installations and generates tokens
    """
    log_access("/github/app", request.remote_addr)

    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        logger.warning(
            f"[ATTACK] GitHub App JWT authentication from {request.remote_addr} - "
            f"token: {auth[7:20]}..."
        )
    else:
        logger.warning(f"[ATTACK] GitHub App info accessed without JWT from {request.remote_addr}")

    return jsonify({
        "id": int(GITHUB_APP_ID),
        "slug": "demo-nhi-app",
        "name": "Demo NHI App",
        "description": "Demo GitHub App for NHI security testing",
        "external_url": "https://example.com/demo-app",
        "html_url": f"https://github.com/apps/demo-nhi-app",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "permissions": {
            "contents": "write",
            "metadata": "read",
            "pull_requests": "write",
            "issues": "write",
            "actions": "write",
            "administration": "read",
            "members": "read",
            "organization_secrets": "read"
        },
        "events": ["push", "pull_request", "issues"],
        "installations_count": 3,
        "owner": {
            "login": "demo-org",
            "id": 98765432,
            "type": "Organization"
        }
    })


@app.route("/github/app/installations", methods=["GET"])
def github_app_installations():
    """
    List GitHub App Installations
    Returns all organizations/users where this App is installed.

    Attackers enumerate installations to find high-value targets.
    """
    log_access("/github/app/installations", request.remote_addr)
    logger.warning(f"[ATTACK] GitHub App installations enumerated from {request.remote_addr}")

    return jsonify([
        {
            "id": 1,
            "account": {
                "login": "demo-org",
                "id": 98765432,
                "type": "Organization"
            },
            "app_id": int(GITHUB_APP_ID),
            "app_slug": "demo-nhi-app",
            "target_type": "Organization",
            "permissions": {
                "contents": "write",
                "metadata": "read",
                "pull_requests": "write",
                "actions": "write",
                "organization_secrets": "read"
            },
            "events": ["push", "pull_request"],
            "repository_selection": "all",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-06-01T00:00:00Z"
        },
        {
            "id": 2,
            "account": {
                "login": "production-org",
                "id": 87654321,
                "type": "Organization"
            },
            "app_id": int(GITHUB_APP_ID),
            "app_slug": "demo-nhi-app",
            "target_type": "Organization",
            "permissions": {
                "contents": "write",
                "metadata": "read",
                "administration": "write"
            },
            "events": ["push"],
            "repository_selection": "selected",
            "created_at": "2024-03-15T00:00:00Z",
            "updated_at": "2024-06-01T00:00:00Z"
        },
        {
            "id": 3,
            "account": {
                "login": "dev-user",
                "id": 76543210,
                "type": "User"
            },
            "app_id": int(GITHUB_APP_ID),
            "app_slug": "demo-nhi-app",
            "target_type": "User",
            "permissions": {
                "contents": "read",
                "metadata": "read"
            },
            "events": ["push"],
            "repository_selection": "selected",
            "created_at": "2024-05-01T00:00:00Z",
            "updated_at": "2024-06-01T00:00:00Z"
        }
    ])


@app.route("/github/app/installations/<installation_id>", methods=["GET"])
def github_app_installation_detail(installation_id: str):
    """
    Get specific GitHub App Installation details
    """
    log_access(f"/github/app/installations/{installation_id}", request.remote_addr)
    logger.warning(f"[ATTACK] GitHub App installation {installation_id} details accessed from {request.remote_addr}")

    return jsonify({
        "id": int(installation_id),
        "account": {
            "login": "demo-org",
            "id": 98765432,
            "type": "Organization"
        },
        "app_id": int(GITHUB_APP_ID),
        "app_slug": "demo-nhi-app",
        "target_type": "Organization",
        "permissions": {
            "contents": "write",
            "metadata": "read",
            "pull_requests": "write",
            "issues": "write",
            "actions": "write",
            "administration": "read",
            "members": "read",
            "organization_secrets": "read"
        },
        "events": ["push", "pull_request", "issues"],
        "repository_selection": "all",
        "single_file_name": None,
        "has_multiple_single_files": False,
        "suspended_at": None,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z"
    })


@app.route("/github/app/installations/<installation_id>/access_tokens", methods=["POST"])
def github_app_token(installation_id: str):
    """
    GitHub App Installation Access Token

    In a real attack:
    1. Attacker compromises GitHub App private key or JWT
    2. Enumerates installations to find high-value targets
    3. Generates installation tokens with broad permissions
    4. Uses tokens to access repos, secrets, and org data
    """
    log_access(f"/github/app/installations/{installation_id}/access_tokens", request.remote_addr)
    logger.warning(
        f"[CRITICAL ATTACK] GitHub App installation token generated for installation {installation_id} "
        f"from {request.remote_addr}"
    )

    # Check for permission narrowing in request body
    data = request.get_json(silent=True) or {}
    requested_permissions = data.get("permissions", {
        "contents": "write",
        "metadata": "read",
        "pull_requests": "write",
        "issues": "write",
        "actions": "write",
        "organization_secrets": "read"
    })
    requested_repos = data.get("repositories", [])
    repo_selection = "selected" if requested_repos else "all"

    return jsonify({
        "token": f"ghs_DEMO_INSTALL_{installation_id}_{uuid.uuid4().hex[:12]}",
        "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z",
        "permissions": requested_permissions,
        "repository_selection": repo_selection,
        "repositories": requested_repos if requested_repos else None,
        "account": {
            "login": "demo-org",
            "id": 98765432,
            "type": "Organization"
        },
        "app_slug": "demo-nhi-app",
        "_demo_note": "This token has broad access - contents:write + org_secrets:read"
    })


@app.route("/github/app/installations/<installation_id>/repositories", methods=["GET"])
def github_app_repositories(installation_id: str):
    """
    List repositories accessible to a GitHub App installation.
    Attackers use this to discover high-value targets.
    """
    log_access(f"/github/app/installations/{installation_id}/repositories", request.remote_addr)
    logger.warning(
        f"[ATTACK] GitHub App repository enumeration for installation {installation_id} "
        f"from {request.remote_addr}"
    )

    return jsonify({
        "total_count": 4,
        "repositories": [
            {
                "id": 100001,
                "name": "infrastructure",
                "full_name": "demo-org/infrastructure",
                "private": True,
                "description": "Production infrastructure (Terraform, K8s configs)",
                "permissions": {"admin": False, "push": True, "pull": True}
            },
            {
                "id": 100002,
                "name": "api-service",
                "full_name": "demo-org/api-service",
                "private": True,
                "description": "Main API service with deployment secrets",
                "permissions": {"admin": False, "push": True, "pull": True}
            },
            {
                "id": 100003,
                "name": "deploy-configs",
                "full_name": "demo-org/deploy-configs",
                "private": True,
                "description": "Deployment configurations with embedded credentials",
                "permissions": {"admin": False, "push": True, "pull": True}
            },
            {
                "id": 100004,
                "name": "public-docs",
                "full_name": "demo-org/public-docs",
                "private": False,
                "description": "Public documentation",
                "permissions": {"admin": False, "push": True, "pull": True}
            }
        ]
    })


# ============================================================
# GitLab CI Mock Endpoints
# ============================================================

@app.route("/gitlab/api/v4/job/token", methods=["GET"])
def gitlab_job_token():
    """
    GitLab CI Job Token - available during CI job execution
    """
    log_access("/gitlab/api/v4/job/token", request.remote_addr)
    logger.warning(f"[ATTACK] GitLab job token accessed from {request.remote_addr}")

    return jsonify({
        "token": GITLAB_CI_TOKEN,
        "token_type": "CI_JOB_TOKEN",
        "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat()
    })


@app.route("/gitlab/api/v4/projects/<project_id>/variables", methods=["GET"])
def gitlab_project_variables(project_id: str):
    """
    GitLab CI/CD Variables - project secrets
    """
    log_access(f"/gitlab/api/v4/projects/{project_id}/variables", request.remote_addr)
    logger.warning(f"[ATTACK] GitLab project variables accessed")

    return jsonify([
        {
            "key": "DEPLOY_TOKEN",
            "value": "gldt-XXXXXXXXXXXXXXXXXXXX",
            "protected": False,
            "masked": True
        },
        {
            "key": "AWS_ACCESS_KEY_ID",
            "value": "AKIADEMO12345GITLAB",
            "protected": True,
            "masked": False
        },
        {
            "key": "DATABASE_PASSWORD",
            "value": "***MASKED***",
            "protected": True,
            "masked": True
        }
    ])


@app.route("/gitlab/api/v4/runners", methods=["GET"])
def gitlab_runners():
    """List GitLab runners"""
    log_access("/gitlab/api/v4/runners", request.remote_addr)

    return jsonify([
        {
            "id": 1,
            "description": "demo-runner-01",
            "ip_address": "172.42.0.10",
            "active": True,
            "is_shared": False,
            "runner_type": "project_type",
            "token": "glrt-XXXXXXXXXXXXXXXXXXXX"
        }
    ])


# ============================================================
# Azure DevOps Mock Endpoints
# ============================================================

@app.route("/azure/pipelines/token", methods=["GET"])
def azure_pipelines_token():
    """
    Azure DevOps Pipeline Token
    """
    log_access("/azure/pipelines/token", request.remote_addr)
    logger.warning(f"[ATTACK] Azure DevOps token accessed")

    return jsonify({
        "token": AZURE_DEVOPS_TOKEN,
        "token_type": "System.AccessToken",
        "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat()
    })


@app.route("/azure/pipelines/<project>/variables", methods=["GET"])
def azure_pipeline_variables(project: str):
    """Azure DevOps Pipeline Variables"""
    log_access(f"/azure/pipelines/{project}/variables", request.remote_addr)

    return jsonify({
        "count": 2,
        "value": [
            {
                "name": "AZURE_SUBSCRIPTION_ID",
                "value": "12345678-demo-1234-demo-123456789012",
                "isSecret": False
            },
            {
                "name": "AZURE_CLIENT_SECRET",
                "value": None,
                "isSecret": True
            }
        ]
    })


# ============================================================
# OIDC Token Endpoints (Workload Identity)
# ============================================================

@app.route("/github/actions/oidc/token", methods=["GET", "POST"])
def github_oidc_token():
    """
    GitHub Actions OIDC Token
    Used for keyless authentication to cloud providers
    """
    log_access("/github/actions/oidc/token", request.remote_addr)
    logger.warning(f"[ATTACK] GitHub OIDC token requested - workload identity abuse")

    audience = request.args.get("audience", "sts.amazonaws.com")

    # Build proper JWT structure
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()

    now = int(datetime.utcnow().timestamp())
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": "repo:demo/test:ref:refs/heads/main",
        "aud": audience,
        "iss": "https://token.actions.githubusercontent.com",
        "exp": now + 3600,
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
        "repository": "demo/test",
        "repository_owner": "demo",
        "repository_owner_id": "12345678",
        "actor": "demo-user",
        "actor_id": "87654321",
        "workflow": "ci.yml",
        "ref": "refs/heads/main",
        "ref_type": "branch",
        "runner_environment": "github-hosted",
        "job_workflow_ref": "demo/test/.github/workflows/ci.yml@refs/heads/main"
    }).encode()).rstrip(b"=").decode()

    signature = "DEMO_SIGNATURE_NOT_VALID"
    oidc_jwt = f"{header}.{payload}.{signature}"

    return jsonify({
        "value": oidc_jwt,
        "count": 1
    })


if __name__ == "__main__":
    print("=" * 60)
    print("Mock CI/CD Server")
    print("NDC Security 2026 - NHI Security Testbed")
    print("=" * 60)
    print("")
    print("Simulates GitHub Actions / GitLab CI / Azure DevOps APIs")
    print("for demonstrating CI/CD token theft attacks.")
    print("")
    print("Listening on port 8080")
    print("=" * 60)

    app.run(host="0.0.0.0", port=8080, debug=False)
