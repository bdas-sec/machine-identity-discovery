"""CTF mode — challenge-based scoring for DEFCON Demo Labs."""

import hashlib
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/ctf", tags=["ctf"])

# In-memory state (reset on restart)
_sessions: dict[str, dict] = {}  # session_id -> {name, score, started, completed, challenges}
_challenge_submissions: dict[str, list] = {}  # session_id -> [{challenge_id, timestamp, correct}]


class SessionCreate(BaseModel):
    name: str
    team: str = ""


class FlagSubmit(BaseModel):
    flag: str


# Challenge definitions
CHALLENGES = [
    {
        "id": "ctf-01",
        "title": "Find the Leaked AWS Key",
        "description": "A cloud workload has an AWS access key in its environment. Find it and submit the key ID.",
        "category": "credential-discovery",
        "points": 100,
        "difficulty": "easy",
        "hint": "Check environment variables on the cloud-workload container",
        "flag_hash": None,  # Dynamic — extracted from container
        "flag_prefix": "AKIA",
        "scenario_ref": "s1-01",
    },
    {
        "id": "ctf-02",
        "title": "IMDS Credential Theft",
        "description": "Steal temporary IAM credentials from the cloud metadata service via SSRF.",
        "category": "cloud-metadata",
        "points": 200,
        "difficulty": "medium",
        "hint": "The vulnerable app on port 8888 has an SSRF endpoint. Target 169.254.169.254",
        "flag_hash": hashlib.sha256(b"NHI{imds_credential_theft_via_ssrf}").hexdigest(),
        "flag_prefix": "NHI{",
        "scenario_ref": "s2-01",
    },
    {
        "id": "ctf-03",
        "title": "Vault Token Heist",
        "description": "Find and use a Vault token to read secrets from HashiCorp Vault.",
        "category": "credential-discovery",
        "points": 200,
        "difficulty": "medium",
        "hint": "Look for VAULT_TOKEN in the cloud workload environment",
        "flag_hash": hashlib.sha256(b"NHI{vault_token_secret_access}").hexdigest(),
        "flag_prefix": "NHI{",
        "scenario_ref": "s1-03",
    },
    {
        "id": "ctf-04",
        "title": "CI/CD Pipeline Takeover",
        "description": "Compromise the CI/CD runner and extract the GitHub token.",
        "category": "cicd",
        "points": 300,
        "difficulty": "medium",
        "hint": "The CI/CD runner has GitHub and GitLab tokens in its environment",
        "flag_hash": hashlib.sha256(b"NHI{cicd_runner_token_compromised}").hexdigest(),
        "flag_prefix": "NHI{",
        "scenario_ref": "s3-01",
    },
    {
        "id": "ctf-05",
        "title": "Kubernetes SA Token Theft",
        "description": "Extract the Kubernetes service account token and query the API server.",
        "category": "kubernetes",
        "points": 300,
        "difficulty": "hard",
        "hint": "Service account tokens live in /var/run/secrets/kubernetes.io/serviceaccount/",
        "flag_hash": hashlib.sha256(b"NHI{k8s_sa_token_rbac_bypass}").hexdigest(),
        "flag_prefix": "NHI{",
        "scenario_ref": "s4-01",
    },
    {
        "id": "ctf-06",
        "title": "SPIFFE Selector Spoofing",
        "description": "Create overlapping SPIRE registration entries to obtain multiple workload identities.",
        "category": "spiffe-spire",
        "points": 400,
        "difficulty": "hard",
        "hint": "Use the SPIRE server CLI to create entries with overlapping unix:uid selectors",
        "flag_hash": hashlib.sha256(b"NHI{spiffe_multi_identity_spoofing}").hexdigest(),
        "flag_prefix": "NHI{",
        "scenario_ref": "s7-01",
    },
    {
        "id": "ctf-07",
        "title": "AI Agent Prompt Injection",
        "description": "Use prompt injection to make the AI agent disclose its credentials.",
        "category": "ai-agent",
        "points": 400,
        "difficulty": "hard",
        "hint": "The AI agent processes user input and has access to environment credentials",
        "flag_hash": hashlib.sha256(b"NHI{ai_agent_credential_disclosure}").hexdigest(),
        "flag_prefix": "NHI{",
        "scenario_ref": "s5-01",
    },
    {
        "id": "ctf-08",
        "title": "Full NHI Kill Chain",
        "description": "Execute the complete 6-stage kill chain: discover, steal, escalate, move, persist, exfiltrate.",
        "category": "kill-chain",
        "points": 500,
        "difficulty": "expert",
        "hint": "Start with credential discovery, pivot through IMDS to cloud, then to CI/CD",
        "flag_hash": hashlib.sha256(b"NHI{complete_nhi_kill_chain_master}").hexdigest(),
        "flag_prefix": "NHI{",
        "scenario_ref": "s6-05",
    },
    {
        "id": "ctf-09",
        "title": "Evade All Detection",
        "description": "Execute an attack chain that triggers ZERO Wazuh alerts. Can you be stealthy?",
        "category": "evasion",
        "points": 500,
        "difficulty": "expert",
        "hint": "Study the detection rules to understand what they look for, then find gaps",
        "flag_hash": hashlib.sha256(b"NHI{detection_evasion_zero_alerts}").hexdigest(),
        "flag_prefix": "NHI{",
        "scenario_ref": None,
    },
    {
        "id": "ctf-10",
        "title": "Cross-Domain Federation Attack",
        "description": "Abuse SPIRE federation to pivot from one trust domain to another.",
        "category": "spiffe-spire",
        "points": 500,
        "difficulty": "expert",
        "hint": "The evil.org SPIRE server federates with the main trust domain",
        "flag_hash": hashlib.sha256(b"NHI{spire_federation_cross_domain}").hexdigest(),
        "flag_prefix": "NHI{",
        "scenario_ref": "s7-11",
    },
]


@router.post("/start")
async def start_session(session: SessionCreate) -> dict[str, Any]:
    """Register a new CTF session."""
    session_id = str(uuid.uuid4())[:8]
    _sessions[session_id] = {
        "name": session.name,
        "team": session.team,
        "score": 0,
        "started": datetime.utcnow().isoformat(),
        "completed": [],
    }
    _challenge_submissions[session_id] = []
    return {"session_id": session_id, "name": session.name, "challenges": len(CHALLENGES)}


@router.get("/challenges")
async def list_challenges(session_id: str = "") -> dict[str, Any]:
    """List all CTF challenges with completion status for a session."""
    completed = set()
    if session_id and session_id in _sessions:
        completed = set(_sessions[session_id]["completed"])

    challenges = []
    for c in CHALLENGES:
        challenges.append({
            "id": c["id"],
            "title": c["title"],
            "description": c["description"],
            "category": c["category"],
            "points": c["points"],
            "difficulty": c["difficulty"],
            "hint": c["hint"],
            "completed": c["id"] in completed,
        })

    total_points = sum(c["points"] for c in CHALLENGES)
    return {"challenges": challenges, "total_points": total_points}


@router.post("/submit/{challenge_id}")
async def submit_flag(challenge_id: str, submission: FlagSubmit, session_id: str = "") -> dict[str, Any]:
    """Submit a flag for a challenge."""
    challenge = next((c for c in CHALLENGES if c["id"] == challenge_id), None)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    if not session_id or session_id not in _sessions:
        raise HTTPException(status_code=400, detail="Invalid session_id")

    # Check if already completed
    if challenge_id in _sessions[session_id]["completed"]:
        return {"correct": True, "message": "Already completed", "points_awarded": 0}

    # Verify flag
    flag_hash = hashlib.sha256(submission.flag.encode()).hexdigest()
    correct = flag_hash == challenge["flag_hash"]

    record = {
        "challenge_id": challenge_id,
        "timestamp": datetime.utcnow().isoformat(),
        "correct": correct,
    }
    _challenge_submissions[session_id].append(record)

    points_awarded = 0
    if correct:
        _sessions[session_id]["completed"].append(challenge_id)
        _sessions[session_id]["score"] += challenge["points"]
        points_awarded = challenge["points"]

    return {
        "correct": correct,
        "message": "Correct! Flag accepted." if correct else "Incorrect flag. Try again.",
        "points_awarded": points_awarded,
        "total_score": _sessions[session_id]["score"],
    }


@router.get("/scoreboard")
async def get_scoreboard() -> dict[str, Any]:
    """Live scoreboard sorted by score descending."""
    board = []
    for sid, data in _sessions.items():
        board.append({
            "session_id": sid,
            "name": data["name"],
            "team": data["team"],
            "score": data["score"],
            "completed": len(data["completed"]),
            "total": len(CHALLENGES),
            "started": data["started"],
        })
    board.sort(key=lambda x: (-x["score"], x["started"]))
    return {"scoreboard": board, "total_sessions": len(board)}


@router.get("/session/{session_id}")
async def get_session(session_id: str) -> dict[str, Any]:
    """Get session details."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    data = _sessions[session_id]
    return {
        **data,
        "session_id": session_id,
        "submissions": _challenge_submissions.get(session_id, []),
    }
