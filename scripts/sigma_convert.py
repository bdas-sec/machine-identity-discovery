#!/usr/bin/env python3
"""
NHI Sigma Rule Conversion Pipeline

Convert Sigma YAML rules to Wazuh XML, Splunk SPL, and Microsoft Sentinel KQL.

Usage:
    python scripts/sigma_convert.py --format all
    python scripts/sigma_convert.py --format splunk --category cloud-imds
    python scripts/sigma_convert.py --format sentinel --output /tmp/sigma-output
    python scripts/sigma_convert.py --list-categories
"""

import argparse
import sys
import time
from pathlib import Path

# Resolve project root for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.sigma_pipeline.backends import ConversionStats, convert_sentinel, convert_splunk, convert_wazuh
from src.sigma_pipeline.loader import CATEGORY_MAP, LoadResult, load_rules

DEFAULT_RULES_DIR = PROJECT_ROOT / "sigma" / "rules"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "sigma" / "output"
DEFAULT_WAZUH_XML = PROJECT_ROOT / "wazuh" / "rules" / "nhi-detection-rules.xml"

VALID_FORMATS = ("wazuh", "splunk", "sentinel", "all")
VALID_CATEGORIES = tuple(CATEGORY_MAP.keys())


def print_stats(stats: ConversionStats) -> None:
    """Print conversion statistics for a single backend."""
    print(f"\n  [{stats.backend_name.upper()}]")
    print(f"    Attempted:         {stats.total_attempted}")
    print(f"    Successful:        {stats.successful}")
    print(f"    Failed:            {stats.failed}")
    print(f"    Correlation stubs: {stats.correlation_stubs}")

    if stats.errors:
        print(f"    Errors:")
        for title, msg in stats.errors[:10]:
            print(f"      - {title}: {msg}")
        if len(stats.errors) > 10:
            print(f"      ... and {len(stats.errors) - 10} more")


def print_summary(load_result: LoadResult, all_stats: dict[str, ConversionStats], elapsed: float) -> None:
    """Print a full summary of the pipeline run."""
    print(f"\n{'=' * 70}")
    print("SIGMA CONVERSION PIPELINE SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Rules loaded:      {load_result.total_loaded}")
    print(f"    Standard:        {len(load_result.standard_rules)}")
    print(f"    Correlation:     {len(load_result.correlation_raw)}")
    print(f"    Load errors:     {load_result.total_errors}")

    for stats in all_stats.values():
        print_stats(stats)

    total_success = sum(s.successful for s in all_stats.values())
    total_failed = sum(s.failed for s in all_stats.values())
    total_corr = sum(s.correlation_stubs for s in all_stats.values())

    print(f"\n  TOTALS across {len(all_stats)} backend(s):")
    print(f"    Queries generated: {total_success}")
    print(f"    Failures:          {total_failed}")
    print(f"    Correlation stubs: {total_corr}")
    print(f"{'=' * 70}")
    print(f"  Completed in {elapsed:.1f}s")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NHI Sigma Rule Conversion Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--format",
        choices=VALID_FORMATS,
        default="all",
        help="Output format: wazuh, splunk, sentinel, or all (default: all)",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_RULES_DIR,
        help=f"Input directory containing Sigma rules (default: sigma/rules/)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output base directory (default: sigma/output/)",
    )
    parser.add_argument(
        "--wazuh-xml",
        type=Path,
        default=DEFAULT_WAZUH_XML,
        help="Existing Wazuh XML rules file for ID-based extraction",
    )
    parser.add_argument(
        "--category",
        choices=VALID_CATEGORIES,
        default=None,
        help="Filter rules by category subdirectory (default: all categories)",
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        help="List available rule categories and exit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed error information",
    )

    args = parser.parse_args()

    if args.list_categories:
        print("\nAvailable rule categories:")
        for dirname, display in CATEGORY_MAP.items():
            category_path = args.input / dirname
            rule_count = len(list(category_path.glob("*.yml"))) if category_path.is_dir() else 0
            print(f"  {dirname:25s} ({display}, {rule_count} rules)")
        return 0

    # Load rules
    start_time = time.monotonic()
    print(f"Loading Sigma rules from {args.input}...")
    if args.category:
        print(f"  Filtering by category: {args.category}")

    load_result = load_rules(args.input, category_filter=args.category)

    print(f"  Loaded {len(load_result.standard_rules)} standard rules")
    print(f"  Found  {len(load_result.correlation_raw)} correlation rules")
    if load_result.errors:
        print(f"  {len(load_result.errors)} load error(s)")
        if args.verbose:
            for path, msg in load_result.errors:
                print(f"    - {path}: {msg}")

    if not load_result.standard_rules and not load_result.correlation_raw:
        print("No rules loaded. Check --input path and --category filter.")
        return 1

    # Run conversions
    formats_to_run = ["wazuh", "splunk", "sentinel"] if args.format == "all" else [args.format]
    all_stats: dict[str, ConversionStats] = {}

    for fmt in formats_to_run:
        output_dir = args.output / fmt
        print(f"\nConverting to {fmt.upper()} -> {output_dir}")

        if fmt == "splunk":
            stats = convert_splunk(load_result.standard_rules, load_result.correlation_raw, output_dir)
        elif fmt == "sentinel":
            stats = convert_sentinel(load_result.standard_rules, load_result.correlation_raw, output_dir)
        elif fmt == "wazuh":
            stats = convert_wazuh(
                load_result.standard_rules, load_result.correlation_raw, args.wazuh_xml, output_dir
            )
        else:
            continue

        all_stats[fmt] = stats
        print(f"  {stats.successful}/{stats.total_attempted} rules converted successfully")

    elapsed = time.monotonic() - start_time
    print_summary(load_result, all_stats, elapsed)

    any_failures = any(s.failed > 0 for s in all_stats.values())
    return 1 if any_failures else 0


if __name__ == "__main__":
    sys.exit(main())
