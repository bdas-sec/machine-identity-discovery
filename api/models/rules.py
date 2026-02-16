"""Pydantic models for detection rules."""

from pydantic import BaseModel, Field


class RuleGroup(BaseModel):
    """A category of detection rules."""

    name: str = Field(description="Group name (e.g., 'credential_discovery')")
    id_range: str = Field(description="Rule ID range (e.g., '100600-100649')")
    count: int = Field(description="Number of rules in this group")
    description: str


class DetectionRule(BaseModel):
    """A Wazuh detection rule summary."""

    id: str = Field(description="Rule ID (e.g., '100600')")
    level: int = Field(description="Wazuh alert level (1-15)")
    description: str
    groups: list[str] = Field(default_factory=list)
    mitre_id: str | None = Field(default=None, description="MITRE ATT&CK technique ID")
    frequency: int | None = Field(default=None, description="Frequency for correlation rules")
    timeframe: str | None = Field(default=None, description="Time window for correlation rules")
