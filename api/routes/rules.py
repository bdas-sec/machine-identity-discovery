"""Detection rule endpoints."""

import xml.etree.ElementTree as ET
from pathlib import Path
from fastapi import APIRouter, HTTPException

from api.config import settings
from api.models.rules import DetectionRule, RuleGroup

router = APIRouter(prefix="/rules", tags=["rules"])

# Rule group metadata
RULE_GROUPS = [
    RuleGroup(name="credential_discovery", id_range="100600-100649", count=10, description="Credential file discovery and enumeration"),
    RuleGroup(name="cloud_imds", id_range="100650-100699", count=9, description="Cloud metadata service (IMDS) access"),
    RuleGroup(name="service_account_misuse", id_range="100700-100749", count=0, description="Service account and IAM misuse"),
    RuleGroup(name="kubernetes", id_range="100750-100799", count=7, description="Kubernetes security events"),
    RuleGroup(name="cicd_pipeline", id_range="100800-100849", count=6, description="CI/CD pipeline security"),
    RuleGroup(name="ai_agent", id_range="100850-100899", count=5, description="AI agent anomalous behavior"),
    RuleGroup(name="secret_patterns", id_range="100900-100949", count=6, description="Secret pattern detection via regex"),
    RuleGroup(name="correlation", id_range="100950-100999", count=5, description="Multi-vector correlation rules"),
]


def parse_rules_xml(path: str) -> list[DetectionRule]:
    """Parse Wazuh XML rule file into DetectionRule models."""
    rules_path = Path(path)
    if not rules_path.exists():
        return []

    try:
        tree = ET.parse(rules_path)
        root = tree.getroot()
    except ET.ParseError:
        return []

    rules = []
    for group_elem in root.findall("group"):
        group_name = group_elem.get("name", "")
        for rule_elem in group_elem.findall("rule"):
            rule_id = rule_elem.get("id", "")
            level = int(rule_elem.get("level", "0"))
            freq = rule_elem.get("frequency")
            timeframe = rule_elem.get("timeframe")

            desc_elem = rule_elem.find("description")
            description = desc_elem.text if desc_elem is not None and desc_elem.text else ""

            groups = [g.strip() for g in group_name.split(",") if g.strip()]
            # Collect group tags within the rule
            for g_elem in rule_elem.findall("group"):
                if g_elem.text:
                    groups.extend(g.strip() for g in g_elem.text.split(",") if g.strip())

            mitre_id = None
            mitre_elem = rule_elem.find(".//mitre/id")
            if mitre_elem is not None and mitre_elem.text:
                mitre_id = mitre_elem.text.strip()

            rules.append(DetectionRule(
                id=rule_id,
                level=level,
                description=description,
                groups=groups,
                mitre_id=mitre_id,
                frequency=int(freq) if freq else None,
                timeframe=timeframe,
            ))

    return rules


@router.get("/groups", response_model=list[RuleGroup])
async def list_rule_groups():
    """List all detection rule groups with metadata."""
    return RULE_GROUPS


@router.get("", response_model=list[DetectionRule])
async def list_rules():
    """List all NHI detection rules parsed from the Wazuh rules XML."""
    rules = parse_rules_xml(settings.rules_file)
    if not rules:
        raise HTTPException(status_code=503, detail="Rules file not found or unparsable")
    return rules


@router.get("/{rule_id}", response_model=DetectionRule)
async def get_rule(rule_id: str):
    """Get a specific detection rule by ID."""
    rules = parse_rules_xml(settings.rules_file)
    for rule in rules:
        if rule.id == rule_id:
            return rule
    raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
