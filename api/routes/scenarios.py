"""Scenario management endpoints."""

import subprocess
from fastapi import APIRouter, HTTPException, Query

from api.config import settings
from api.models.scenarios import (
    Scenario,
    ScenarioLevel,
    ScenarioResult,
    ScenarioRun,
    ValidationSummary,
)

router = APIRouter(prefix="/scenarios", tags=["scenarios"])

# Scenario registry — mirrors run_demo.py definitions.
# In a future iteration this will load from scenario JSON files.
SCENARIOS: dict[str, Scenario] = {
    "s1-01": Scenario(
        id="s1-01", name="Environment File Enumeration", level=ScenarioLevel.CREDENTIAL_DISCOVERY,
        target="cloud-workload",
        commands=["find /app -name '*.env*' 2>/dev/null || true", "cat /app/.env 2>/dev/null || echo 'No .env found'"],
        description="Scan for .env files containing credentials",
        detection_rules=["100600"], mitre_techniques=["T1552.001"],
    ),
    "s1-02": Scenario(
        id="s1-02", name="AWS Credentials Discovery", level=ScenarioLevel.CREDENTIAL_DISCOVERY,
        target="cloud-workload",
        commands=["ls -la ~/.aws/ 2>/dev/null || echo 'No AWS config'", "cat ~/.aws/credentials 2>/dev/null || echo 'No credentials file'"],
        description="Search for AWS credential files",
        detection_rules=["100601"], mitre_techniques=["T1552.001"],
    ),
    "s1-03": Scenario(
        id="s1-03", name="SSH Key Discovery", level=ScenarioLevel.CREDENTIAL_DISCOVERY,
        target="cloud-workload",
        commands=["find /root/.ssh -type f 2>/dev/null || echo 'No SSH dir'", "ls -la /root/.ssh/ 2>/dev/null || true"],
        description="Enumerate SSH private keys",
        detection_rules=["100602"], mitre_techniques=["T1552.004"],
    ),
    "s1-04": Scenario(
        id="s1-04", name="Git Credentials Discovery", level=ScenarioLevel.CREDENTIAL_DISCOVERY,
        target="cicd-runner",
        commands=["cat ~/.git-credentials 2>/dev/null || echo 'No git credentials'", "cat ~/.gitconfig 2>/dev/null || echo 'No gitconfig'"],
        description="Search for git credential helpers",
        detection_rules=["100603"], mitre_techniques=["T1552.001"],
    ),
    "s1-05": Scenario(
        id="s1-05", name="Kubernetes Config Discovery", level=ScenarioLevel.CREDENTIAL_DISCOVERY,
        target="cloud-workload",
        commands=["cat ~/.kube/config 2>/dev/null || echo 'No kubeconfig'"],
        description="Find kubeconfig files",
        detection_rules=["100605"], mitre_techniques=["T1552.001"],
    ),
    "s2-01": Scenario(
        id="s2-01", name="IMDS Credential Theft (AWS)", level=ScenarioLevel.CREDENTIAL_THEFT,
        target="cloud-workload",
        commands=[
            "curl -s http://mock-imds:1338/latest/meta-data/",
            "curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/",
            "ROLE=$(curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/); curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/$ROLE",
        ],
        description="Extract IAM credentials from AWS IMDS",
        detection_rules=["100650", "100651", "100658"], mitre_techniques=["T1552.005"],
    ),
    "s2-02": Scenario(
        id="s2-02", name="Process Environment Harvesting", level=ScenarioLevel.CREDENTIAL_THEFT,
        target="cloud-workload",
        commands=["env | grep -iE 'key|token|secret|password' || true", "cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | head -20 || echo 'Cannot read environ'"],
        description="Extract secrets from process environment",
        detection_rules=["100607"], mitre_techniques=["T1552.007"],
    ),
    "s2-03": Scenario(
        id="s2-03", name="Kubernetes ServiceAccount Token Theft", level=ScenarioLevel.CREDENTIAL_THEFT,
        target="cloud-workload",
        commands=["cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo 'No SA token'"],
        description="Extract K8s service account token",
        detection_rules=["100750", "100751"], mitre_techniques=["T1528"],
    ),
    "s2-04": Scenario(
        id="s2-04", name="CI/CD Token Extraction", level=ScenarioLevel.CREDENTIAL_THEFT,
        target="cicd-runner",
        commands=["env | grep -i github || true", "env | grep -i token || true"],
        description="Extract GitHub/GitLab tokens",
        detection_rules=["100800", "100802"], mitre_techniques=["T1528"],
    ),
    "s2-05": Scenario(
        id="s2-05", name="Vault Token Theft", level=ScenarioLevel.CREDENTIAL_THEFT,
        target="cloud-workload",
        commands=["cat ~/.vault-token 2>/dev/null || echo 'No vault token'", "env | grep VAULT || true"],
        description="Steal HashiCorp Vault tokens",
        detection_rules=["100606"], mitre_techniques=["T1555"],
    ),
    "s3-01": Scenario(
        id="s3-01", name="IMDS Role Assumption", level=ScenarioLevel.PRIVILEGE_ESCALATION,
        target="cloud-workload",
        commands=["CREDS=$(curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/demo-ec2-role); echo $CREDS | head -c 200"],
        description="Use stolen IMDS credentials",
        detection_rules=["100651", "100657"], mitre_techniques=["T1078.004"],
    ),
    "s3-02": Scenario(
        id="s3-02", name="Kubernetes RBAC Probing", level=ScenarioLevel.PRIVILEGE_ESCALATION,
        target="cloud-workload",
        commands=["kubectl auth can-i --list 2>/dev/null || echo 'kubectl not available'"],
        description="Enumerate K8s permissions",
        detection_rules=["100752", "100755"], mitre_techniques=["T1069.003"],
    ),
    "s3-03": Scenario(
        id="s3-03", name="Kubernetes Secrets Enumeration", level=ScenarioLevel.PRIVILEGE_ESCALATION,
        target="cloud-workload",
        commands=["kubectl get secrets -A 2>/dev/null || echo 'Cannot list secrets'"],
        description="List and extract K8s secrets",
        detection_rules=["100753"], mitre_techniques=["T1087.004"],
    ),
    "s3-04": Scenario(
        id="s3-04", name="Vault Privilege Escalation", level=ScenarioLevel.PRIVILEGE_ESCALATION,
        target="cloud-workload",
        commands=["TOKEN=$(cat ~/.vault-token 2>/dev/null); curl -s -H \"X-Vault-Token: $TOKEN\" http://vault:8200/v1/secret/data/production 2>/dev/null || echo 'Vault access failed'"],
        description="Use stolen vault token",
        detection_rules=["100606"], mitre_techniques=["T1555"],
    ),
    "s3-05": Scenario(
        id="s3-05", name="Multiple Credential Harvest", level=ScenarioLevel.PRIVILEGE_ESCALATION,
        target="cloud-workload",
        commands=["cat ~/.aws/credentials 2>/dev/null || true; cat ~/.ssh/id_rsa 2>/dev/null | head -5 || true; cat ~/.git-credentials 2>/dev/null || true; cat ~/.vault-token 2>/dev/null || true; cat /app/.env 2>/dev/null || true"],
        description="Rapid enumeration of credentials",
        detection_rules=["100609"], mitre_techniques=["T1552.001"],
    ),
    "s4-01": Scenario(
        id="s4-01", name="Cross-Network Movement", level=ScenarioLevel.LATERAL_MOVEMENT,
        target="cicd-runner",
        commands=["curl -s http://cloud-workload:8080/ 2>/dev/null || echo 'Cannot reach cloud workload'"],
        description="Access cloud workload from CI/CD",
        detection_rules=[], mitre_techniques=["T1021"],
    ),
    "s4-02": Scenario(
        id="s4-02", name="Stolen SSH Key Usage", level=ScenarioLevel.LATERAL_MOVEMENT,
        target="cloud-workload",
        commands=["cat ~/.ssh/id_rsa 2>/dev/null | head -3 || echo 'No SSH key'"],
        description="Use discovered SSH keys",
        detection_rules=["100602"], mitre_techniques=["T1552.004"],
    ),
    "s4-03": Scenario(
        id="s4-03", name="Git Credential Abuse", level=ScenarioLevel.LATERAL_MOVEMENT,
        target="cicd-runner",
        commands=["cat ~/.git-credentials 2>/dev/null || echo 'No credentials'"],
        description="Use stolen git credentials",
        detection_rules=["100603"], mitre_techniques=["T1552.001"],
    ),
    "s4-04": Scenario(
        id="s4-04", name="Docker Registry Authentication", level=ScenarioLevel.LATERAL_MOVEMENT,
        target="cicd-runner",
        commands=["cat ~/.docker/config.json 2>/dev/null || echo 'No docker config'"],
        description="Use stolen Docker config",
        detection_rules=["100604"], mitre_techniques=["T1552.001"],
    ),
    "s4-05": Scenario(
        id="s4-05", name="API Key Abuse", level=ScenarioLevel.LATERAL_MOVEMENT,
        target="vulnerable-app",
        commands=["env | grep -iE 'api|key|token' || true"],
        description="Extract and identify API keys",
        detection_rules=[], mitre_techniques=["T1552.001"],
    ),
    "s5-01": Scenario(
        id="s5-01", name="Pipeline Poisoning", level=ScenarioLevel.PERSISTENCE,
        target="cicd-runner",
        commands=["find /runner -name '*.yml' 2>/dev/null | head -5 || true"],
        description="Identify pipeline configs for modification",
        detection_rules=["100803"], mitre_techniques=["T1195.002"],
    ),
    "s5-02": Scenario(
        id="s5-02", name="Credential Rotation Backdoor", level=ScenarioLevel.PERSISTENCE,
        target="cloud-workload",
        commands=["cat ~/.aws/credentials 2>/dev/null || echo 'No AWS creds'"],
        description="Identify credential persistence locations",
        detection_rules=["100601"], mitre_techniques=["T1098"],
    ),
    "s5-03": Scenario(
        id="s5-03", name="Service Account Token Persistence", level=ScenarioLevel.PERSISTENCE,
        target="cloud-workload",
        commands=["cp /var/run/secrets/kubernetes.io/serviceaccount/token /tmp/sa_token 2>/dev/null || echo 'No SA token'"],
        description="Copy SA tokens for persistence",
        detection_rules=["100750"], mitre_techniques=["T1528"],
    ),
    "s5-04": Scenario(
        id="s5-04", name="Environment Variable Injection", level=ScenarioLevel.PERSISTENCE,
        target="vulnerable-app",
        commands=["env | wc -l"],
        description="Identify env var injection points",
        detection_rules=[], mitre_techniques=["T1059"],
    ),
}


@router.get("", response_model=list[Scenario])
async def list_scenarios(level: int | None = Query(None, ge=1, le=5, description="Filter by kill chain level")):
    """List all available attack scenarios, optionally filtered by level."""
    scenarios = list(SCENARIOS.values())
    if level is not None:
        scenarios = [s for s in scenarios if s.level == level]
    return scenarios


@router.get("/{scenario_id}", response_model=Scenario)
async def get_scenario(scenario_id: str):
    """Get a specific scenario by ID."""
    scenario = SCENARIOS.get(scenario_id.lower())
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    return scenario


@router.post("/{scenario_id}/run", response_model=ScenarioResult)
async def run_scenario(scenario_id: str, body: ScenarioRun | None = None):
    """Execute a scenario against its target container."""
    if body is None:
        body = ScenarioRun()

    scenario = SCENARIOS.get(scenario_id.lower())
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")

    runtime = settings.container_runtime
    succeeded = 0
    output_lines: list[str] = []

    for cmd in scenario.commands:
        try:
            result = subprocess.run(
                [runtime, "exec", scenario.target, "bash", "-c", cmd],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                succeeded += 1
            if body.verbose:
                output_lines.append(result.stdout[:500] if result.stdout else "")
        except subprocess.TimeoutExpired:
            output_lines.append(f"[timeout] {cmd[:60]}")
        except Exception as e:
            output_lines.append(f"[error] {e}")

    status = "success" if succeeded == len(scenario.commands) else "partial" if succeeded > 0 else "error"

    return ScenarioResult(
        scenario_id=scenario.id,
        status=status,
        commands_executed=len(scenario.commands),
        commands_succeeded=succeeded,
        output=output_lines if body.verbose else [],
    )
