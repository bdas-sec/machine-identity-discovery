#!/usr/bin/env python3
"""
Detection Coverage Matrix Generator.

Generates a matrix mapping scenarios -> expected Wazuh rules -> test coverage -> OCSF classes.
Outputs both Markdown table and JSON report formats.

Usage:
    python tests/reports/generate_coverage_matrix.py
    python tests/reports/generate_coverage_matrix.py --format json
    python tests/reports/generate_coverage_matrix.py --format markdown
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


PROJECT_ROOT = Path(__file__).parent.parent.parent
SCENARIOS_DIR = PROJECT_ROOT / "scenarios"
TESTS_DIR = PROJECT_ROOT / "tests" / "e2e"
RULES_FILE = PROJECT_ROOT / "wazuh" / "rules" / "nhi-detection-rules.xml"
OCSF_MAPPING_FILE = PROJECT_ROOT / "ocsf" / "event-mapping.yml"
SIGMA_DIR = PROJECT_ROOT / "sigma" / "rules"


# OCSF class UID to name mapping (fallback if YAML unavailable)
OCSF_CLASS_NAMES = {
    1001: "File Activity",
    1007: "Process Activity",
    2001: "Security Finding",
    3002: "Authentication",
    4001: "Network Activity",
    6001: "Web Resources Activity",
    6003: "API Activity",
}


def load_scenarios():
    """Load all scenario JSON files."""
    scenarios = []
    for json_file in sorted(SCENARIOS_DIR.rglob("*.json")):
        with open(json_file) as f:
            try:
                data = json.load(f)
                if "id" in data:
                    scenarios.append(data)
            except json.JSONDecodeError:
                pass
    return sorted(scenarios, key=lambda s: s["id"])


def extract_test_scenario_ids():
    """Extract SCENARIO_ID values from test files."""
    test_ids = {}
    for test_file in sorted(TESTS_DIR.rglob("test_scenarios.py")):
        content = test_file.read_text()
        # Find all class names and their SCENARIO_IDs
        classes = re.findall(
            r'class\s+(Test\w+).*?SCENARIO_ID\s*=\s*"(S\d-\d+)"',
            content,
            re.DOTALL,
        )
        for class_name, scenario_id in classes:
            # Count test methods in this class
            class_match = re.search(
                rf'class\s+{class_name}.*?(?=\nclass\s|\Z)',
                content,
                re.DOTALL,
            )
            if class_match:
                method_count = len(
                    re.findall(r'def\s+test_', class_match.group())
                )
            else:
                method_count = 0

            test_ids[scenario_id] = {
                "class": class_name,
                "file": str(test_file.relative_to(PROJECT_ROOT)),
                "method_count": method_count,
            }
    return test_ids


def extract_correlation_test_ids():
    """Extract correlation rule test info."""
    corr_file = TESTS_DIR / "correlation" / "test_correlation_rules.py"
    if not corr_file.exists():
        return {}

    content = corr_file.read_text()
    rules = {}
    classes = re.findall(
        r'class\s+(TestCorrelationRule\w+).*?RULE_ID\s*=\s*"(\d+)"',
        content,
        re.DOTALL,
    )
    for class_name, rule_id in classes:
        class_match = re.search(
            rf'class\s+{class_name}.*?(?=\nclass\s|\Z)',
            content,
            re.DOTALL,
        )
        method_count = (
            len(re.findall(r'def\s+test_', class_match.group()))
            if class_match
            else 0
        )
        rules[rule_id] = {
            "class": class_name,
            "method_count": method_count,
        }
    return rules


def extract_wazuh_rules():
    """Extract rule IDs and descriptions from Wazuh rules XML."""
    rules = {}
    if not RULES_FILE.exists():
        return rules

    content = RULES_FILE.read_text()
    matches = re.findall(
        r'<rule\s+id="(\d+)"[^>]*level="(\d+)"[^>]*>.*?'
        r'<description>(.*?)</description>',
        content,
        re.DOTALL,
    )
    for rule_id, level, description in matches:
        rules[rule_id] = {
            "level": int(level),
            "description": description.strip(),
        }
    return rules


def load_ocsf_mapping():
    """Load OCSF event-mapping.yml and build rule_id -> OCSF class mapping."""
    ocsf_map = {}  # rule_id (str) -> {"class_uid": int, "class_name": str, "severity_id": int}

    if not OCSF_MAPPING_FILE.exists():
        return ocsf_map

    if not HAS_YAML:
        # Fallback: parse with regex
        content = OCSF_MAPPING_FILE.read_text()
        for match in re.finditer(
            r'rule_id:\s*(\d+)\s*\n.*?ocsf_class_uid:\s*(\d+)',
            content, re.DOTALL
        ):
            rid, class_uid = match.group(1), int(match.group(2))
            ocsf_map[rid] = {
                "class_uid": class_uid,
                "class_name": OCSF_CLASS_NAMES.get(class_uid, f"Class {class_uid}"),
            }
        return ocsf_map

    with open(OCSF_MAPPING_FILE) as f:
        data = yaml.safe_load(f)

    if not data or "rule_mappings" not in data:
        return ocsf_map

    for group_name, group_data in data["rule_mappings"].items():
        default_class_uid = group_data.get("default_ocsf_class_uid")
        default_class_name = group_data.get("default_ocsf_class_name", "")
        for rule in group_data.get("rules", []):
            rid = str(rule["rule_id"])
            class_uid = rule.get("ocsf_class_uid", default_class_uid)
            class_name = OCSF_CLASS_NAMES.get(class_uid, default_class_name)
            ocsf_map[rid] = {
                "class_uid": class_uid,
                "class_name": class_name,
                "severity_id": rule.get("ocsf_severity_id"),
            }

    return ocsf_map


def count_sigma_rules():
    """Count Sigma rule files."""
    if not SIGMA_DIR.exists():
        return 0
    return len(list(SIGMA_DIR.rglob("*.yml")))


def generate_matrix():
    """Generate the full detection coverage matrix."""
    scenarios = load_scenarios()
    test_ids = extract_test_scenario_ids()
    corr_rules = extract_correlation_test_ids()
    wazuh_rules = extract_wazuh_rules()
    ocsf_map = load_ocsf_mapping()
    sigma_count = count_sigma_rules()

    matrix = {
        "summary": {
            "total_scenarios": len(scenarios),
            "scenarios_with_tests": 0,
            "scenarios_without_tests": 0,
            "total_expected_rules": 0,
            "total_test_methods": 0,
            "correlation_rules_tested": len(corr_rules),
            "total_wazuh_rules": len(wazuh_rules),
            "ocsf_mapped_rules": len(ocsf_map),
            "sigma_rules": sigma_count,
        },
        "scenarios": [],
        "correlation_rules": [],
        "untested_scenarios": [],
        "ocsf_classes_used": {},
    }

    for scenario in scenarios:
        sid = scenario["id"]
        expected_alerts = scenario.get("expected_wazuh_alerts", [])
        expected_rule_ids = [str(a["rule_id"]) for a in expected_alerts]

        has_test = sid in test_ids
        test_info = test_ids.get(sid, {})

        # Determine OCSF classes for this scenario's rules
        scenario_ocsf = set()
        for rid in expected_rule_ids:
            if rid in ocsf_map:
                class_uid = ocsf_map[rid]["class_uid"]
                class_name = ocsf_map[rid]["class_name"]
                scenario_ocsf.add(f"{class_uid} ({class_name})")
                # Track global OCSF class usage
                key = str(class_uid)
                if key not in matrix["ocsf_classes_used"]:
                    matrix["ocsf_classes_used"][key] = {
                        "class_uid": class_uid,
                        "class_name": class_name,
                        "scenario_count": 0,
                        "rule_count": 0,
                    }
                matrix["ocsf_classes_used"][key]["scenario_count"] += 1
                matrix["ocsf_classes_used"][key]["rule_count"] += 1

        entry = {
            "id": sid,
            "name": scenario["name"],
            "category": scenario.get("category", "Unknown"),
            "difficulty": scenario.get("difficulty", "Unknown"),
            "expected_rules": expected_rule_ids,
            "expected_rule_count": len(expected_rule_ids),
            "has_e2e_test": has_test,
            "test_class": test_info.get("class", ""),
            "test_file": test_info.get("file", ""),
            "test_method_count": test_info.get("method_count", 0),
            "ocsf_classes": sorted(scenario_ocsf),
        }

        # Add rule details with OCSF
        entry["rule_details"] = []
        for rid in expected_rule_ids:
            rule_info = wazuh_rules.get(rid, {})
            ocsf_info = ocsf_map.get(rid, {})
            entry["rule_details"].append({
                "rule_id": rid,
                "level": rule_info.get("level", "?"),
                "description": rule_info.get("description", "Unknown"),
                "ocsf_class_uid": ocsf_info.get("class_uid", ""),
                "ocsf_class_name": ocsf_info.get("class_name", ""),
            })

        matrix["scenarios"].append(entry)
        matrix["summary"]["total_expected_rules"] += len(expected_rule_ids)
        matrix["summary"]["total_test_methods"] += entry["test_method_count"]

        if has_test:
            matrix["summary"]["scenarios_with_tests"] += 1
        else:
            matrix["summary"]["scenarios_without_tests"] += 1
            matrix["untested_scenarios"].append(sid)

    # Correlation rules — include 100955 from Phase 3
    for rule_id in ["100950", "100951", "100952", "100953", "100954", "100955"]:
        rule_info = wazuh_rules.get(rule_id, {})
        corr_test = corr_rules.get(rule_id, {})
        ocsf_info = ocsf_map.get(rule_id, {})
        matrix["correlation_rules"].append({
            "rule_id": rule_id,
            "level": rule_info.get("level", "?"),
            "description": rule_info.get("description", "Unknown"),
            "has_test": rule_id in corr_rules,
            "test_class": corr_test.get("class", ""),
            "test_method_count": corr_test.get("method_count", 0),
            "ocsf_class_uid": ocsf_info.get("class_uid", ""),
            "ocsf_class_name": ocsf_info.get("class_name", ""),
        })

    # Calculate coverage percentage
    total = matrix["summary"]["total_scenarios"]
    tested = matrix["summary"]["scenarios_with_tests"]
    matrix["summary"]["coverage_pct"] = (
        round(tested / total * 100, 1) if total > 0 else 0
    )

    return matrix


def format_markdown(matrix):
    """Format matrix as Markdown."""
    lines = []
    lines.append("# NHI Detection Coverage Matrix")
    lines.append("")

    # Summary
    s = matrix["summary"]
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total scenarios | {s['total_scenarios']} |")
    lines.append(f"| Scenarios with E2E tests | {s['scenarios_with_tests']} |")
    lines.append(f"| Scenarios without tests | {s['scenarios_without_tests']} |")
    lines.append(f"| E2E coverage | **{s['coverage_pct']}%** |")
    lines.append(f"| Total expected rules | {s['total_expected_rules']} |")
    lines.append(f"| Total Wazuh rules | {s['total_wazuh_rules']} |")
    lines.append(f"| OCSF-mapped rules | {s['ocsf_mapped_rules']} |")
    lines.append(f"| Sigma rules | {s['sigma_rules']} |")
    lines.append(f"| Total test methods | {s['total_test_methods']} |")
    lines.append(f"| Correlation rules tested | {s['correlation_rules_tested']}/6 |")
    lines.append("")

    # Scenario coverage table
    lines.append("## Scenario Coverage")
    lines.append("")
    lines.append(
        "| ID | Scenario | Category | Difficulty | Expected Rules | "
        "OCSF Classes | E2E Test | Methods |"
    )
    lines.append(
        "|-----|----------|----------|------------|---------------|"
        "-------------|---------|---------|"
    )
    for entry in matrix["scenarios"]:
        rules_str = ", ".join(entry["expected_rules"]) or "none"
        ocsf_str = ", ".join(
            str(c.split(" ")[0]) for c in entry["ocsf_classes"]
        ) if entry["ocsf_classes"] else "-"
        test_status = "Y" if entry["has_e2e_test"] else "**N**"
        lines.append(
            f"| {entry['id']} | {entry['name'][:35]} | "
            f"{entry['category'][:15]} | {entry['difficulty']} | "
            f"{rules_str} | {ocsf_str} | {test_status} | "
            f"{entry['test_method_count']} |"
        )
    lines.append("")

    # Correlation rules
    lines.append("## Correlation Rules")
    lines.append("")
    lines.append(
        "| Rule ID | Level | Description | OCSF | Tested | Methods |"
    )
    lines.append(
        "|---------|-------|-------------|------|--------|---------|"
    )
    for rule in matrix["correlation_rules"]:
        tested = "Y" if rule["has_test"] else "**N**"
        ocsf = str(rule["ocsf_class_uid"]) if rule["ocsf_class_uid"] else "-"
        lines.append(
            f"| {rule['rule_id']} | {rule['level']} | "
            f"{rule['description'][:50]} | {ocsf} | {tested} | "
            f"{rule['test_method_count']} |"
        )
    lines.append("")

    # OCSF class usage
    if matrix["ocsf_classes_used"]:
        lines.append("## OCSF Event Classes")
        lines.append("")
        lines.append("| Class UID | Class Name | Scenarios | Rules |")
        lines.append("|-----------|-----------|-----------|-------|")
        for uid in sorted(matrix["ocsf_classes_used"]):
            cls = matrix["ocsf_classes_used"][uid]
            lines.append(
                f"| {cls['class_uid']} | {cls['class_name']} | "
                f"{cls['scenario_count']} | {cls['rule_count']} |"
            )
        lines.append("")

    # Untested scenarios
    if matrix["untested_scenarios"]:
        lines.append("## Untested Scenarios")
        lines.append("")
        for sid in matrix["untested_scenarios"]:
            lines.append(f"- {sid}")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate NHI detection coverage matrix"
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json", "both"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).parent,
        help="Output directory for reports",
    )
    args = parser.parse_args()

    matrix = generate_matrix()

    if args.format in ("json", "both"):
        json_path = args.output_dir / "detection_coverage.json"
        with open(json_path, "w") as f:
            json.dump(matrix, f, indent=2)
        print(f"JSON report: {json_path}")

    if args.format in ("markdown", "both"):
        md_path = args.output_dir / "detection_coverage.md"
        with open(md_path, "w") as f:
            f.write(format_markdown(matrix))
        print(f"Markdown report: {md_path}")

    # Print summary to stdout
    s = matrix["summary"]
    print(f"\nCoverage: {s['scenarios_with_tests']}/{s['total_scenarios']} "
          f"scenarios ({s['coverage_pct']}%)")
    print(f"Test methods: {s['total_test_methods']}")
    print(f"Wazuh rules: {s['total_wazuh_rules']} "
          f"({s['ocsf_mapped_rules']} OCSF-mapped)")
    print(f"Sigma rules: {s['sigma_rules']}")
    print(f"Correlation rules tested: {s['correlation_rules_tested']}/6")
    if matrix["untested_scenarios"]:
        print(f"Untested: {', '.join(matrix['untested_scenarios'])}")


if __name__ == "__main__":
    main()
