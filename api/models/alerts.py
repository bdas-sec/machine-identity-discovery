"""Pydantic models for alerts."""

from datetime import datetime
from pydantic import BaseModel, Field


class Alert(BaseModel):
    """A Wazuh alert."""

    id: str
    timestamp: datetime
    rule_id: str
    rule_description: str
    rule_level: int
    agent_name: str
    agent_id: str
    groups: list[str] = Field(default_factory=list)
    full_log: str | None = None


class AlertSummary(BaseModel):
    """Paginated alert listing."""

    total: int
    alerts: list[Alert]
    offset: int = 0
    limit: int = 20


class ValidationResult(BaseModel):
    """Result of validating alerts against expected rules."""

    scenario_id: str
    expected_rules: list[str]
    detected_rules: list[str]
    missed_rules: list[str]
    passed: bool
