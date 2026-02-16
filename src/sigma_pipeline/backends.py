"""Backend orchestration — convert Sigma rules to Splunk SPL, Sentinel KQL, and Wazuh XML."""

from dataclasses import dataclass, field
from pathlib import Path

from sigma.backends.microsoft365defender.microsoft365defender import Microsoft365DefenderBackend
from sigma.backends.splunk import SplunkBackend
from sigma.rule import SigmaRule

from src.sigma_pipeline.correlation import CorrelationOutput, generate_correlation_stubs
from src.sigma_pipeline.mapping import nhi_sentinel_pipeline, nhi_splunk_pipeline
from src.sigma_pipeline.wazuh import assemble_wazuh_output, convert_to_wazuh_xml


@dataclass
class ConversionStats:
    """Statistics for a single backend conversion run."""

    backend_name: str
    total_attempted: int = 0
    successful: int = 0
    failed: int = 0
    correlation_stubs: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)


def _format_rule_header(rule: SigmaRule, comment_prefix: str) -> str:
    """Build a metadata header comment for a converted rule."""
    level_name = rule.level.name if rule.level else "unknown"
    tags_str = ", ".join(str(t) for t in (rule.tags or []))
    return (
        f"{comment_prefix} {rule.title}\n"
        f"{comment_prefix} Sigma ID: {rule.id}\n"
        f"{comment_prefix} Level: {level_name}\n"
        f"{comment_prefix} Tags: {tags_str}"
    )


def _write_correlation_stubs(
    corr_outputs: list[CorrelationOutput],
    output_dir: Path,
    backend_name: str,
) -> int:
    """Write correlation stubs to a file. Returns count written."""
    if not corr_outputs:
        return 0

    ext_map = {"splunk": "spl", "sentinel": "kql", "wazuh": "xml"}
    ext = ext_map.get(backend_name, "txt")
    attr_map = {"splunk": "splunk_stub", "sentinel": "sentinel_stub", "wazuh": "wazuh_stub"}
    attr = attr_map[backend_name]

    stubs = [getattr(co, attr) for co in corr_outputs]
    corr_file = output_dir / f"nhi_correlation_stubs.{ext}"
    corr_file.write_text("\n\n".join(stubs) + "\n", encoding="utf-8")
    return len(stubs)


def convert_splunk(
    rules: list[SigmaRule],
    correlation_rules: list[dict],
    output_dir: Path,
) -> ConversionStats:
    """Convert standard rules to Splunk SPL and write correlation stubs."""
    stats = ConversionStats(backend_name="splunk")
    output_dir.mkdir(parents=True, exist_ok=True)

    pipeline = nhi_splunk_pipeline()
    backend = SplunkBackend(processing_pipeline=pipeline)
    queries: list[str] = []

    for rule in rules:
        stats.total_attempted += 1
        try:
            result = backend.convert_rule(rule)
            if result:
                query_str = result[0] if isinstance(result, list) else str(result)
                header = _format_rule_header(rule, "#")
                queries.append(f"{header}\n{query_str}")
                stats.successful += 1
            else:
                stats.errors.append((str(rule.title), "Backend returned empty result"))
                stats.failed += 1
        except Exception as e:
            stats.errors.append((str(rule.title), str(e)))
            stats.failed += 1

    output_file = output_dir / "nhi_rules.spl"
    output_file.write_text("\n\n".join(queries) + "\n", encoding="utf-8")

    corr_outputs = generate_correlation_stubs(correlation_rules)
    stats.correlation_stubs = _write_correlation_stubs(corr_outputs, output_dir, "splunk")

    return stats


def convert_sentinel(
    rules: list[SigmaRule],
    correlation_rules: list[dict],
    output_dir: Path,
) -> ConversionStats:
    """Convert standard rules to Microsoft Sentinel KQL and write correlation stubs."""
    stats = ConversionStats(backend_name="sentinel")
    output_dir.mkdir(parents=True, exist_ok=True)

    pipeline = nhi_sentinel_pipeline()
    backend = Microsoft365DefenderBackend(processing_pipeline=pipeline)
    queries: list[str] = []

    for rule in rules:
        stats.total_attempted += 1
        try:
            result = backend.convert_rule(rule)
            if result:
                query_str = result[0] if isinstance(result, list) else str(result)
                header = _format_rule_header(rule, "//")
                queries.append(f"{header}\n{query_str}")
                stats.successful += 1
            else:
                stats.errors.append((str(rule.title), "Backend returned empty result"))
                stats.failed += 1
        except Exception as e:
            stats.errors.append((str(rule.title), str(e)))
            stats.failed += 1

    output_file = output_dir / "nhi_rules.kql"
    output_file.write_text("\n\n".join(queries) + "\n", encoding="utf-8")

    corr_outputs = generate_correlation_stubs(correlation_rules)
    stats.correlation_stubs = _write_correlation_stubs(corr_outputs, output_dir, "sentinel")

    return stats


def convert_wazuh(
    rules: list[SigmaRule],
    correlation_rules: list[dict],
    wazuh_xml_path: Path,
    output_dir: Path,
) -> ConversionStats:
    """Convert standard rules to Wazuh XML via ID-based extraction from existing rules."""
    stats = ConversionStats(backend_name="wazuh")
    output_dir.mkdir(parents=True, exist_ok=True)

    conversion = convert_to_wazuh_xml(rules, wazuh_xml_path)
    stats.total_attempted = len(rules)
    stats.successful = conversion.mapped_count
    stats.failed = len(conversion.unmapped_rules)
    stats.errors = list(conversion.errors)

    xml_output = assemble_wazuh_output(conversion)
    output_file = output_dir / "nhi_rules.xml"
    output_file.write_text(xml_output, encoding="utf-8")

    corr_outputs = generate_correlation_stubs(correlation_rules)
    stats.correlation_stubs = _write_correlation_stubs(corr_outputs, output_dir, "wazuh")

    return stats
