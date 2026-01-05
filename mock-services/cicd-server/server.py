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


def log_access(endpoint: str, source_ip: str):
    """Log all CI/CD API access"""
    logger.warning(f"CI/CD ACCESS: {source_ip} -> {endpoint}")


@app.route("/")
def index():
    """Root endpoint"""
    return jsonify({
        "service": "Mock CI/CD Server",
        "version": "1.0.0",
        "description": "NDC Security 2026 - NHI Testbed",
        "endpoints": {
            "/": "This page",
            "/health": "Health check",
            "/github/actions/runner/token": "GitHub Actions runner token",
            "/github/repos/<owner>/<repo>/actions/secrets": "GitHub repo secrets",
            "/gitlab/api/v4/job/token": "GitLab CI job token",
            "/gitlab/api/v4/projects/<id>/variables": "GitLab CI variables",
            "/azure/pipelines/token": "Azure DevOps token"
        }
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy"})


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


@app.route("/github/app/installations/<installation_id>/access_tokens", methods=["POST"])
def github_app_token(installation_id: str):
    """
    GitHub App Installation Access Token
    """
    log_access(f"/github/app/installations/{installation_id}/access_tokens", request.remote_addr)
    logger.warning(f"[ATTACK] GitHub App installation token requested")

    return jsonify({
        "token": "ghs_DEMOINSTALLATIONTOKEN1234567890ABCDEF",
        "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z",
        "permissions": {
            "contents": "write",
            "metadata": "read",
            "pull_requests": "write"
        },
        "repository_selection": "all"
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

    # Mock OIDC JWT token
    return jsonify({
        "value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXBvOmRlbW8vdGVzdDpyZWY6cmVmcy9oZWFkcy9tYWluIiwiYXVkIjoiIiwiZXhwIjoxNzAwMDAwMDAwfQ.DEMO_SIGNATURE",
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
