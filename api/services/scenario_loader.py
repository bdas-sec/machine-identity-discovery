"""Load scenario definitions from JSON files and the built-in SCENARIOS dict."""

import json
from pathlib import Path

from api.config import settings

# Rule ID range -> category name mapping
RULE_CATEGORIES = {
    (100600, 100649): "Credential Discovery",
    (100650, 100699): "Cloud Metadata (IMDS)",
    (100700, 100749): "Service Account Misuse",
    (100750, 100799): "Kubernetes Security",
    (100800, 100849): "CI/CD Pipeline",
    (100850, 100899): "AI Agent Anomalies",
    (100900, 100949): "Secret Pattern Detection",
    (100950, 100999): "Correlation Rules",
}

# Hardcoded scenarios for when JSON files are missing.
# These match the definitions in run_demo.py.
BUILTIN_SCENARIOS: dict[str, dict] = {
    "s1-01": {"id": "s1-01", "name": "Environment File Enumeration", "level": 1, "target": "cloud-workload",
              "commands": ["find /app -name '*.env*' 2>/dev/null || true", "cat /app/.env 2>/dev/null || echo 'No .env found'"],
              "description": "Scan for .env files containing credentials", "detection_rules": ["100600"]},
    "s1-02": {"id": "s1-02", "name": "AWS Credentials Discovery", "level": 1, "target": "cloud-workload",
              "commands": ["ls -la ~/.aws/ 2>/dev/null || echo 'No AWS config'", "cat ~/.aws/credentials 2>/dev/null || echo 'No credentials file'"],
              "description": "Search for AWS credential files", "detection_rules": ["100601"]},
    "s1-03": {"id": "s1-03", "name": "SSH Key Discovery", "level": 1, "target": "cloud-workload",
              "commands": ["find /root/.ssh -type f 2>/dev/null || echo 'No SSH dir'"],
              "description": "Enumerate SSH private keys", "detection_rules": ["100602"]},
    "s1-04": {"id": "s1-04", "name": "Git Credentials Discovery", "level": 1, "target": "cicd-runner",
              "commands": ["cat ~/.git-credentials 2>/dev/null || echo 'No git credentials'"],
              "description": "Search for git credential helpers", "detection_rules": ["100603"]},
    "s1-05": {"id": "s1-05", "name": "Kubernetes Config Discovery", "level": 1, "target": "cloud-workload",
              "commands": ["cat ~/.kube/config 2>/dev/null || echo 'No kubeconfig'"],
              "description": "Find kubeconfig files", "detection_rules": ["100605"]},
    "s2-01": {"id": "s2-01", "name": "IMDS Credential Theft (AWS)", "level": 2, "target": "cloud-workload",
              "commands": ["curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/"],
              "description": "Extract IAM credentials from AWS IMDS", "detection_rules": ["100650", "100651", "100658"]},
    "s2-02": {"id": "s2-02", "name": "Process Environment Harvesting", "level": 2, "target": "cloud-workload",
              "commands": ["cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | head -20 || true"],
              "description": "Extract secrets from process environment", "detection_rules": ["100607"]},
    "s2-03": {"id": "s2-03", "name": "Kubernetes ServiceAccount Token Theft", "level": 2, "target": "cloud-workload",
              "commands": ["cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true"],
              "description": "Extract K8s service account token", "detection_rules": ["100750", "100751"]},
    "s2-04": {"id": "s2-04", "name": "CI/CD Token Extraction", "level": 2, "target": "cicd-runner",
              "commands": ["env | grep -i github || true", "env | grep -i token || true"],
              "description": "Extract GitHub/GitLab tokens", "detection_rules": ["100800", "100802"]},
    "s2-05": {"id": "s2-05", "name": "Vault Token Theft", "level": 2, "target": "cloud-workload",
              "commands": ["cat ~/.vault-token 2>/dev/null || true"],
              "description": "Steal HashiCorp Vault tokens", "detection_rules": ["100606"]},
    "s3-01": {"id": "s3-01", "name": "IMDS Role Assumption", "level": 3, "target": "cloud-workload",
              "commands": ["curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/demo-ec2-role"],
              "description": "Use stolen IMDS credentials", "detection_rules": ["100651", "100657"]},
    "s3-02": {"id": "s3-02", "name": "Kubernetes RBAC Probing", "level": 3, "target": "cloud-workload",
              "commands": ["kubectl auth can-i --list 2>/dev/null || true"],
              "description": "Enumerate K8s permissions", "detection_rules": ["100752", "100755"]},
    "s3-03": {"id": "s3-03", "name": "Kubernetes Secrets Enumeration", "level": 3, "target": "cloud-workload",
              "commands": ["kubectl get secrets -A 2>/dev/null || true"],
              "description": "List and extract K8s secrets", "detection_rules": ["100753"]},
    "s3-04": {"id": "s3-04", "name": "Vault Privilege Escalation", "level": 3, "target": "cloud-workload",
              "commands": ["curl -s http://vault:8200/v1/secret/data/production 2>/dev/null || true"],
              "description": "Use stolen vault token", "detection_rules": ["100606"]},
    "s3-05": {"id": "s3-05", "name": "Multiple Credential Harvest", "level": 3, "target": "cloud-workload",
              "commands": ["cat ~/.aws/credentials 2>/dev/null; cat ~/.ssh/id_rsa 2>/dev/null | head -5; cat ~/.vault-token 2>/dev/null"],
              "description": "Rapid enumeration of credentials", "detection_rules": ["100609"]},
    "s4-01": {"id": "s4-01", "name": "Cross-Network Movement", "level": 4, "target": "cicd-runner",
              "commands": ["curl -s http://172.41.0.10:8080/ 2>/dev/null || true"],
              "description": "Access cloud workload from CI/CD", "detection_rules": []},
    "s4-02": {"id": "s4-02", "name": "Stolen SSH Key Usage", "level": 4, "target": "cloud-workload",
              "commands": ["cat ~/.ssh/id_rsa 2>/dev/null | head -3 || true"],
              "description": "Use discovered SSH keys", "detection_rules": ["100602"]},
    "s4-03": {"id": "s4-03", "name": "Git Credential Abuse", "level": 4, "target": "cicd-runner",
              "commands": ["cat ~/.git-credentials 2>/dev/null || true"],
              "description": "Use stolen git credentials", "detection_rules": ["100603"]},
    "s4-04": {"id": "s4-04", "name": "Docker Registry Authentication", "level": 4, "target": "cicd-runner",
              "commands": ["cat ~/.docker/config.json 2>/dev/null || true"],
              "description": "Use stolen Docker config", "detection_rules": ["100604"]},
    "s4-05": {"id": "s4-05", "name": "API Key Abuse", "level": 4, "target": "vulnerable-app",
              "commands": ["env | grep -iE 'api|key|token' || true"],
              "description": "Extract and identify API keys", "detection_rules": []},
    "s5-01": {"id": "s5-01", "name": "Pipeline Poisoning", "level": 5, "target": "cicd-runner",
              "commands": ["find /runner -name '*.yml' 2>/dev/null | head -5 || true"],
              "description": "Identify pipeline configs for modification", "detection_rules": ["100803"]},
    "s5-02": {"id": "s5-02", "name": "Credential Rotation Backdoor", "level": 5, "target": "cloud-workload",
              "commands": ["cat ~/.aws/credentials 2>/dev/null || true"],
              "description": "Identify credential persistence locations", "detection_rules": ["100601"]},
    "s5-03": {"id": "s5-03", "name": "Service Account Token Persistence", "level": 5, "target": "cloud-workload",
              "commands": ["cp /var/run/secrets/kubernetes.io/serviceaccount/token /tmp/sa_token 2>/dev/null || true"],
              "description": "Copy SA tokens for persistence", "detection_rules": ["100750"]},
    "s5-04": {"id": "s5-04", "name": "Environment Variable Injection", "level": 5, "target": "vulnerable-app",
              "commands": ["env | wc -l"],
              "description": "Identify env var injection points", "detection_rules": []},
}


class ScenarioLoader:
    """Loads and caches scenario definitions."""

    def __init__(self):
        self._scenarios: dict[str, dict] = {}

    @property
    def scenarios(self) -> dict[str, dict]:
        if not self._scenarios:
            self.load_all()
        return self._scenarios

    def load_all(self):
        """Load scenarios from JSON files, falling back to built-in definitions."""
        self._scenarios.clear()

        # 1. Load from JSON files on disk
        scenarios_dir = Path(settings.scenarios_dir)
        if scenarios_dir.is_dir():
            for json_file in sorted(scenarios_dir.rglob("*.json")):
                try:
                    data = json.loads(json_file.read_text())
                    sid = data.get("id", "").lower().replace("s", "s", 1)
                    if sid:
                        self._scenarios[sid] = data
                except (json.JSONDecodeError, KeyError):
                    continue

        # 2. Fill gaps with built-in definitions
        for sid, data in BUILTIN_SCENARIOS.items():
            key = sid.lower()
            if key not in self._scenarios:
                self._scenarios[key] = data

    def list_all(self) -> list[dict]:
        """Return all scenarios sorted by ID."""
        return sorted(self.scenarios.values(), key=lambda s: s.get("id", ""))

    def get(self, scenario_id: str) -> dict | None:
        """Get a scenario by ID (case-insensitive)."""
        return self.scenarios.get(scenario_id.lower())

    def list_by_level(self, level: int) -> list[dict]:
        """Return scenarios for a given kill-chain level."""
        return [s for s in self.list_all() if s.get("level") == level]


# Singleton used across the application
scenario_loader = ScenarioLoader()
