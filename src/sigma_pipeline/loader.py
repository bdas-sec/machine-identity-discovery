"""Load and classify Sigma YAML rules from the rules directory."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from sigma.rule import SigmaRule


CATEGORY_MAP: dict[str, str] = {
    "credential-discovery": "Credential Discovery",
    "cloud-imds": "Cloud IMDS",
    "kubernetes": "Kubernetes",
    "cicd-pipeline": "CI/CD Pipeline",
    "secret-patterns": "Secret Patterns",
    "ai-agent": "AI Agent",
    "correlation": "Correlation",
}


@dataclass
class LoadResult:
    """Result of loading and classifying Sigma rules."""

    standard_rules: list[SigmaRule] = field(default_factory=list)
    correlation_raw: list[dict] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total_loaded(self) -> int:
        return len(self.standard_rules) + len(self.correlation_raw)

    @property
    def total_errors(self) -> int:
        return len(self.errors)


def load_rules(rules_dir: Path, category_filter: str | None = None) -> LoadResult:
    """Load Sigma rules from a directory tree, optionally filtering by category.

    Args:
        rules_dir: Root directory containing category subdirectories of YAML rules.
        category_filter: If provided, only load rules from this category subdirectory.

    Returns:
        LoadResult with classified rules and any load errors.
    """
    result = LoadResult()

    if not rules_dir.is_dir():
        result.errors.append((str(rules_dir), "Directory does not exist"))
        return result

    if category_filter:
        dirs_to_scan = [rules_dir / category_filter]
    else:
        dirs_to_scan = sorted(p for p in rules_dir.iterdir() if p.is_dir() and not p.name.startswith("."))

    for category_dir in dirs_to_scan:
        if not category_dir.is_dir():
            result.errors.append((str(category_dir), "Category directory not found"))
            continue

        for yml_file in sorted(category_dir.glob("*.yml")):
            try:
                raw = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                if not isinstance(raw, dict):
                    result.errors.append((str(yml_file), "YAML did not parse to a dict"))
                    continue

                if raw.get("type") == "correlation":
                    raw["_source_file"] = str(yml_file)
                    raw["_category"] = category_dir.name
                    result.correlation_raw.append(raw)
                else:
                    # collect_errors=True allows rules with non-UUID related IDs
                    rule = SigmaRule.from_yaml(yml_file.read_text(encoding="utf-8"), collect_errors=True)
                    result.standard_rules.append(rule)
            except Exception as e:
                result.errors.append((str(yml_file), str(e)))

    return result
