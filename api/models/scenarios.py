"""Pydantic models for attack scenarios."""

from enum import IntEnum
from pydantic import BaseModel, Field


class ScenarioLevel(IntEnum):
    CREDENTIAL_DISCOVERY = 1
    CREDENTIAL_THEFT = 2
    PRIVILEGE_ESCALATION = 3
    LATERAL_MOVEMENT = 4
    PERSISTENCE = 5


class Scenario(BaseModel):
    """An NHI attack scenario definition."""

    id: str = Field(description="Scenario identifier (e.g., s2-01)")
    name: str = Field(description="Human-readable scenario name")
    level: ScenarioLevel = Field(description="Kill chain level (1-5)")
    target: str = Field(description="Target container name")
    commands: list[str] = Field(description="Commands to execute in the target container")
    description: str = Field(description="What this scenario demonstrates")
    detection_rules: list[str] = Field(
        default_factory=list, description="Expected Wazuh rule IDs that should fire"
    )
    mitre_techniques: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique IDs"
    )


class ScenarioRun(BaseModel):
    """Request to run a scenario."""

    validate_alerts: bool = Field(
        default=False, description="Poll Wazuh API to verify alerts after execution"
    )
    verbose: bool = Field(default=False, description="Include command output in response")


class ScenarioResult(BaseModel):
    """Result of running a scenario."""

    scenario_id: str
    status: str = Field(description="'success', 'partial', or 'error'")
    commands_executed: int
    commands_succeeded: int
    output: list[str] = Field(default_factory=list, description="Command outputs (if verbose)")
    validation: "ValidationSummary | None" = None


class ValidationSummary(BaseModel):
    """Summary of alert validation for a scenario run."""

    expected_rules: list[str]
    detected_rules: list[str]
    missed_rules: list[str]
    passed: bool
