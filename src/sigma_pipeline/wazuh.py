"""Custom Wazuh XML backend — extracts rules from existing Wazuh XML using Sigma->Wazuh ID mapping.

Since no official pySigma Wazuh backend exists, this module uses a pragmatic approach:
it reads the Wazuh rule ID from each Sigma rule's `related` field and extracts the
corresponding <rule> element from the existing nhi-detection-rules.xml file.
"""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from sigma.rule import SigmaRule


@dataclass
class WazuhConversionResult:
    """Result of converting Sigma rules to Wazuh XML."""

    xml_fragments: list[str] = field(default_factory=list)
    mapped_count: int = 0
    unmapped_rules: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)


def extract_wazuh_rule_id(sigma_rule: SigmaRule) -> str | None:
    """Extract the related Wazuh rule ID from a Sigma rule's 'related' field.

    With collect_errors=True, rule.related is a list of plain dicts like:
        [{"id": "100601", "type": "derived"}]
    """
    for rel in getattr(sigma_rule, "related", []) or []:
        if isinstance(rel, dict):
            if str(rel.get("type", "")).lower() == "derived":
                return str(rel["id"])
        elif hasattr(rel, "type") and str(rel.type).lower() == "derived":
            return str(rel.id)
    return None


def parse_wazuh_rules_by_id(xml_path: Path) -> dict[str, ET.Element]:
    """Parse the Wazuh XML rules file and index <rule> elements by ID.

    The Wazuh rules file has multiple top-level <group> elements without a single
    document root, so we wrap it in a <rules> element for parsing.
    """
    if not xml_path.exists():
        return {}

    raw_xml = xml_path.read_text(encoding="utf-8")
    # Strip XML comments at top level to avoid parse issues
    raw_xml = re.sub(r"<!--.*?-->", "", raw_xml, flags=re.DOTALL)
    wrapped = f"<rules>{raw_xml}</rules>"

    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        return {}

    index: dict[str, ET.Element] = {}
    for group_elem in root.findall("group"):
        for rule_elem in group_elem.findall("rule"):
            rule_id = rule_elem.get("id", "")
            if rule_id:
                index[rule_id] = rule_elem

    return index


def convert_to_wazuh_xml(sigma_rules: list[SigmaRule], wazuh_xml_path: Path) -> WazuhConversionResult:
    """Convert Sigma rules to Wazuh XML by extracting corresponding rules from existing XML.

    Args:
        sigma_rules: List of parsed SigmaRule objects (standard rules only).
        wazuh_xml_path: Path to the existing nhi-detection-rules.xml.
    """
    result = WazuhConversionResult()
    wazuh_index = parse_wazuh_rules_by_id(wazuh_xml_path)

    for sigma_rule in sigma_rules:
        wazuh_id = extract_wazuh_rule_id(sigma_rule)

        if wazuh_id and wazuh_id in wazuh_index:
            elem = wazuh_index[wazuh_id]
            xml_str = ET.tostring(elem, encoding="unicode")
            level_name = sigma_rule.level.name if sigma_rule.level else "unknown"
            header = f"  <!-- Sigma: {sigma_rule.title} | ID: {sigma_rule.id} | Level: {level_name} -->"
            result.xml_fragments.append(f"{header}\n  {xml_str}")
            result.mapped_count += 1
        elif wazuh_id:
            result.errors.append((str(sigma_rule.title), f"Wazuh ID {wazuh_id} not found in {wazuh_xml_path}"))
        else:
            result.unmapped_rules.append(str(sigma_rule.title))

    return result


def assemble_wazuh_output(conversion: WazuhConversionResult) -> str:
    """Assemble XML fragments into a complete Wazuh rules file."""
    lines = [
        "<!-- NHI Detection Rules — Generated from Sigma via pySigma pipeline -->",
        f"<!-- Mapped: {conversion.mapped_count} rules | Unmapped: {len(conversion.unmapped_rules)} -->",
        "",
        '<group name="nhi,sigma_generated,">',
    ]
    lines.extend(conversion.xml_fragments)
    lines.append("</group>")
    return "\n".join(lines) + "\n"
