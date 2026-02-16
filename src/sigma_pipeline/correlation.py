"""Handle Sigma correlation rules — generate SIEM-specific documentation stubs.

Correlation rules (type: correlation) cannot be processed by standard pySigma backends.
This module generates placeholder queries for Splunk, Sentinel, and Wazuh that document
the correlation logic and require manual implementation.
"""

from dataclasses import dataclass, field


@dataclass
class CorrelationOutput:
    """Generated documentation for a single correlation rule across SIEMs."""

    title: str
    sigma_id: str
    wazuh_id: str | None
    referenced_rules: list[str]
    group_by: list[str]
    timespan: str
    condition: dict
    level: str
    splunk_stub: str = ""
    sentinel_stub: str = ""
    wazuh_stub: str = ""


def generate_correlation_stubs(correlation_rules: list[dict]) -> list[CorrelationOutput]:
    """Generate SIEM-specific documentation stubs for correlation rules.

    Args:
        correlation_rules: Raw YAML dicts for rules with type=correlation.
    """
    outputs: list[CorrelationOutput] = []

    for raw in correlation_rules:
        title = raw.get("title", "Unknown")
        sigma_id = raw.get("id", "")
        wazuh_id = None
        for rel in raw.get("related", []):
            if rel.get("type") == "derived":
                wazuh_id = str(rel["id"])

        referenced = raw.get("rules", [])
        group_by = raw.get("group-by", [])
        timespan = raw.get("timespan", "unknown")
        condition = raw.get("condition", {})
        level = raw.get("level", "unknown")
        threshold = condition.get("gte", 1)

        # Splunk correlation search stub
        rule_names_spl = " OR ".join(f'rule_name="{r}"' for r in referenced)
        group_by_spl = ", ".join(group_by) if group_by else "host"
        splunk_stub = (
            f"# {title}\n"
            f"# Sigma ID: {sigma_id} | Wazuh ID: {wazuh_id or 'N/A'} | Level: {level}\n"
            f"# NOTE: Requires manual implementation as a Splunk correlation search\n"
            f'| tstats count where ({rule_names_spl}) by {group_by_spl} _time span={timespan}\n'
            f"| where count >= {threshold}"
        )

        # Sentinel KQL stub
        rule_names_kql = ", ".join(f'"{r}"' for r in referenced)
        group_by_kql = ", ".join(group_by) if group_by else "Computer"
        sentinel_stub = (
            f"// {title}\n"
            f"// Sigma ID: {sigma_id} | Wazuh ID: {wazuh_id or 'N/A'} | Level: {level}\n"
            f"// NOTE: Requires implementation as a Sentinel Analytics Rule\n"
            f"let timewindow = {timespan};\n"
            f"SecurityAlert\n"
            f"| where AlertName in ({rule_names_kql})\n"
            f"| summarize AlertCount=count() by {group_by_kql}, bin(TimeGenerated, timewindow)\n"
            f"| where AlertCount >= {threshold}"
        )

        # Wazuh stub (reference to existing correlation rule)
        wazuh_stub = (
            f"<!-- Correlation: {title} -->\n"
            f"<!-- Wazuh rule {wazuh_id or 'N/A'} already implements this correlation -->\n"
            f'<!-- Referenced rules: {", ".join(referenced)} -->\n'
            f'<!-- group-by: {", ".join(group_by)} | timespan: {timespan} | threshold: {threshold} -->'
        )

        outputs.append(CorrelationOutput(
            title=title,
            sigma_id=sigma_id,
            wazuh_id=wazuh_id,
            referenced_rules=referenced,
            group_by=group_by,
            timespan=timespan,
            condition=condition,
            level=level,
            splunk_stub=splunk_stub,
            sentinel_stub=sentinel_stub,
            wazuh_stub=wazuh_stub,
        ))

    return outputs
