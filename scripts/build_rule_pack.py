#!/usr/bin/env python3
"""
Build the NHI Detection Rule Pack as a distributable archive.

Creates a self-contained .tar.gz (and optionally .zip) archive containing:
  - Sigma YAML source rules organized by category
  - Pre-converted rules for Splunk (SPL), Sentinel (KQL), and Wazuh (XML)
  - Standalone conversion CLI for re-converting rules
  - manifest.json with version, rule counts, categories, MITRE ATT&CK mappings

Usage:
    python scripts/build_rule_pack.py                    # Build with existing outputs
    python scripts/build_rule_pack.py --regenerate       # Re-run sigma conversion first
    python scripts/build_rule_pack.py --format zip       # Also create .zip
    python scripts/build_rule_pack.py --output-dir /tmp  # Custom output location
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIGMA_RULES_DIR = PROJECT_ROOT / "sigma" / "rules"
SIGMA_OUTPUT_DIR = PROJECT_ROOT / "sigma" / "output"
PIPELINE_DIR = PROJECT_ROOT / "src" / "sigma_pipeline"
DIST_DIR = PROJECT_ROOT / "dist"

VERSION = "0.1.0"
PACK_NAME = "nhi-detection-rules"


def get_git_sha() -> str:
    """Get short git SHA of current commit."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def _try_load_yaml():
    """Try to import yaml, return None if unavailable."""
    try:
        import yaml
        return yaml
    except ImportError:
        return None


def _parse_yaml_file(content: str, yaml_mod):
    """Parse a YAML file, using pyyaml if available, else regex fallback."""
    if yaml_mod:
        raw = yaml_mod.safe_load(content)
        return raw if isinstance(raw, dict) else None

    # Regex fallback for simple top-level Sigma rule fields
    result = {}

    m = re.search(r'^title:\s*["\']?(.+?)["\']?\s*$', content, re.MULTILINE)
    if m:
        result["title"] = m.group(1).strip()

    m = re.search(r'^id:\s*(.+)$', content, re.MULTILINE)
    if m:
        result["id"] = m.group(1).strip()

    m = re.search(r'^level:\s*(\w+)', content, re.MULTILINE)
    if m:
        result["level"] = m.group(1).strip()

    m = re.search(r'^status:\s*(\w+)', content, re.MULTILINE)
    if m:
        result["status"] = m.group(1).strip()

    m = re.search(r'^author:\s*(.+)$', content, re.MULTILINE)
    if m:
        result["author"] = m.group(1).strip()

    m = re.search(r'^type:\s*(\w+)', content, re.MULTILINE)
    if m:
        result["type"] = m.group(1).strip()

    # Extract tags as a list
    tags = re.findall(r'^\s+-\s+(attack\.\S+|nhi\.\S+)', content, re.MULTILINE)
    if tags:
        result["tags"] = tags

    # Extract related derived IDs
    related_ids = re.findall(r'^\s+-\s*id:\s*["\']?(\d+)["\']?\s*$', content, re.MULTILINE)
    if related_ids:
        result["related"] = [{"id": rid, "type": "derived"} for rid in related_ids]

    return result if result else None


def parse_sigma_tags(rules_dir: Path) -> dict:
    """Extract MITRE ATT&CK mappings and stats from all Sigma YAML rules."""
    yaml_mod = _try_load_yaml()

    categories = {}
    mitre_techniques = set()
    mitre_tactics = set()
    rule_levels = {"informational": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    total_rules = 0
    authors = set()

    for category_dir in sorted(rules_dir.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("."):
            continue

        category_rules = []
        for yml_file in sorted(category_dir.glob("*.yml")):
            try:
                content = yml_file.read_text(encoding="utf-8")
                raw = _parse_yaml_file(content, yaml_mod)
                if not raw:
                    continue

                total_rules += 1
                rule_info = {
                    "id": raw.get("id", ""),
                    "title": raw.get("title", ""),
                    "level": raw.get("level", "unknown"),
                    "status": raw.get("status", "unknown"),
                }

                # Extract MITRE tags
                for tag in raw.get("tags", []):
                    tag_str = str(tag).lower()
                    if tag_str.startswith("attack.t"):
                        mitre_techniques.add(tag_str.replace("attack.", "").upper())
                    elif tag_str.startswith("attack.") and not tag_str.startswith("attack.t"):
                        mitre_tactics.add(tag_str.replace("attack.", ""))

                # Count levels
                level = raw.get("level", "unknown")
                if level in rule_levels:
                    rule_levels[level] += 1

                # Extract related Wazuh rule IDs
                for rel in raw.get("related", []):
                    if isinstance(rel, dict) and rel.get("type") == "derived":
                        rule_info["wazuh_rule_id"] = str(rel["id"])

                if raw.get("author"):
                    authors.add(raw["author"])

                category_rules.append(rule_info)
            except Exception:
                continue

        if category_rules:
            categories[category_dir.name] = {
                "rule_count": len(category_rules),
                "rules": category_rules,
            }

    return {
        "total_rules": total_rules,
        "categories": categories,
        "mitre_techniques": sorted(mitre_techniques),
        "mitre_tactics": sorted(mitre_tactics),
        "rule_levels": rule_levels,
        "authors": sorted(authors),
    }


def generate_manifest(rules_dir: Path) -> dict:
    """Generate the manifest.json metadata for the rule pack."""
    stats = parse_sigma_tags(rules_dir)

    # Summarize categories without individual rule lists
    category_summary = {}
    for cat_name, cat_data in stats["categories"].items():
        category_summary[cat_name] = {
            "rule_count": cat_data["rule_count"],
            "display_name": cat_name.replace("-", " ").title(),
        }

    manifest = {
        "name": PACK_NAME,
        "version": VERSION,
        "description": "NHI Detection Rule Pack — Sigma rules for Non-Human Identity (NHI) security threats",
        "build_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "git_sha": get_git_sha(),
        "schema_version": "1.0",
        "stats": {
            "total_sigma_rules": stats["total_rules"],
            "categories": len(category_summary),
            "mitre_techniques": len(stats["mitre_techniques"]),
            "mitre_tactics": len(stats["mitre_tactics"]),
            "rule_levels": stats["rule_levels"],
        },
        "categories": category_summary,
        "mitre_attack": {
            "techniques": stats["mitre_techniques"],
            "tactics": stats["mitre_tactics"],
        },
        "siem_targets": {
            "splunk": {"format": "SPL", "file": "converted/splunk/nhi_rules.spl"},
            "sentinel": {"format": "KQL", "file": "converted/sentinel/nhi_rules.kql"},
            "wazuh": {"format": "XML", "file": "converted/wazuh/nhi_rules.xml"},
        },
        "authors": stats["authors"],
        "license": "MIT",
        "homepage": "https://github.com/your-org/machine-identity-discovery",
    }

    return manifest


def compute_checksums(archive_path: Path) -> dict:
    """Compute SHA256 and MD5 checksums for an archive."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()  # noqa: S324

    with open(archive_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)

    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}


def regenerate_outputs() -> bool:
    """Re-run sigma_convert.py to regenerate pre-converted outputs."""
    script = PROJECT_ROOT / "scripts" / "sigma_convert.py"
    if not script.exists():
        print("  WARNING: sigma_convert.py not found, skipping regeneration")
        return False

    print("  Running sigma conversion pipeline...")
    result = subprocess.run(
        [sys.executable, str(script), "--format", "all"],
        capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=120,
    )

    if result.returncode != 0:
        print(f"  WARNING: Conversion had issues (exit code {result.returncode})")
        if result.stderr:
            print(f"  {result.stderr[:500]}")
        return False

    print("  Conversion complete")
    return True


def create_standalone_readme() -> str:
    """Generate README content for the standalone rule pack."""
    return f"""# NHI Detection Rule Pack v{VERSION}

Detection rules for **Non-Human Identity (NHI)** security threats — machine identities,
service accounts, API keys, cloud metadata credentials, CI/CD tokens, and AI agent anomalies.

## Contents

```
{PACK_NAME}-{VERSION}/
├── manifest.json            # Pack metadata, MITRE mappings, stats
├── README.md                # This file
├── rules/                   # Sigma YAML source rules
│   ├── credential-discovery/
│   ├── cloud-imds/
│   ├── kubernetes/
│   ├── cicd-pipeline/
│   ├── secret-patterns/
│   ├── ai-agent/
│   └── correlation/
├── converted/               # Pre-converted SIEM rules
│   ├── splunk/              # Splunk SPL queries
│   ├── sentinel/            # Microsoft Sentinel KQL queries
│   └── wazuh/               # Wazuh XML rules
└── pipeline/                # pySigma converter (optional)
    ├── __init__.py
    ├── loader.py
    ├── backends.py
    ├── mapping.py
    ├── wazuh.py
    ├── correlation.py
    └── convert.py           # Standalone CLI
```

## Quick Start

### Import pre-converted rules

**Splunk:**
```bash
# Copy SPL queries into your Splunk saved searches
cat converted/splunk/nhi_rules.spl
```

**Microsoft Sentinel:**
```bash
# Import KQL queries as Analytics Rules
cat converted/sentinel/nhi_rules.kql
```

**Wazuh:**
```bash
# Copy XML rules to your Wazuh manager
cp converted/wazuh/nhi_rules.xml /var/ossec/etc/rules/nhi-detection-rules.xml
systemctl restart wazuh-manager
```

### Re-convert rules (optional)

If you need to customize field mappings or target a specific backend:

```bash
pip install pySigma pySigma-backend-splunk pySigma-backend-microsoft365defender pyyaml

# Convert all rules to all backends
python pipeline/convert.py --rules-dir rules/ --output-dir output/ --format all

# Convert specific category
python pipeline/convert.py --rules-dir rules/ --format splunk --category cloud-imds
```

## MITRE ATT&CK Coverage

See `manifest.json` for the full mapping. Key techniques covered:

- **T1552** — Unsecured Credentials (files, metadata, cloud)
- **T1528** — Steal Application Access Token
- **T1550** — Use Alternate Authentication Material
- **T1078** — Valid Accounts (cloud, default)
- **T1059** — Command and Scripting Interpreter
- **T1611** — Escape to Host (container breakout)

## License

MIT — See the main project repository for full license text.
"""


def build_archive(
    output_dir: Path,
    regenerate: bool = False,
    create_zip: bool = False,
) -> list[Path]:
    """Build the NHI Detection Rule Pack archive.

    Returns list of created archive paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    pack_dir_name = f"{PACK_NAME}-{VERSION}"
    staging = output_dir / pack_dir_name

    # Clean staging area
    if staging.exists():
        shutil.rmtree(staging)

    print(f"\nBuilding NHI Detection Rule Pack v{VERSION}")
    print(f"{'=' * 60}")

    # Regenerate outputs if requested
    if regenerate:
        print("\n[1/5] Regenerating converted outputs...")
        regenerate_outputs()
    else:
        print("\n[1/5] Using existing converted outputs")

    # Copy Sigma source rules
    print("\n[2/5] Copying Sigma source rules...")
    rules_dest = staging / "rules"
    if SIGMA_RULES_DIR.exists():
        shutil.copytree(SIGMA_RULES_DIR, rules_dest)
        rule_count = sum(1 for _ in rules_dest.rglob("*.yml"))
        print(f"  Copied {rule_count} rules across {sum(1 for _ in rules_dest.iterdir() if _.is_dir())} categories")
    else:
        print("  WARNING: sigma/rules/ not found!")
        rules_dest.mkdir(parents=True)

    # Copy pre-converted outputs
    print("\n[3/5] Copying pre-converted SIEM rules...")
    converted_dest = staging / "converted"
    converted_dest.mkdir(parents=True)

    for siem_dir in ["splunk", "sentinel", "wazuh"]:
        src = SIGMA_OUTPUT_DIR / siem_dir
        dst = converted_dest / siem_dir
        if src.exists():
            shutil.copytree(src, dst)
            file_count = sum(1 for _ in dst.iterdir() if _.is_file())
            print(f"  {siem_dir}: {file_count} files")
        else:
            dst.mkdir(parents=True)
            print(f"  {siem_dir}: no outputs found (run with --regenerate)")

    # Copy pipeline code
    print("\n[4/5] Bundling pySigma converter pipeline...")
    pipeline_dest = staging / "pipeline"
    pipeline_dest.mkdir(parents=True)

    for py_file in PIPELINE_DIR.glob("*.py"):
        dest_file = pipeline_dest / py_file.name
        # Rewrite imports for standalone use
        content = py_file.read_text(encoding="utf-8")
        content = content.replace("from src.sigma_pipeline.", "from ")
        dest_file.write_text(content, encoding="utf-8")
        print(f"  Bundled {py_file.name}")

    # Create standalone convert.py CLI
    convert_cli = pipeline_dest / "convert.py"
    convert_cli.write_text(_standalone_convert_cli(), encoding="utf-8")
    print("  Created standalone convert.py CLI")

    # Generate manifest and README
    print("\n[5/5] Generating manifest and README...")
    manifest = generate_manifest(SIGMA_RULES_DIR)
    manifest_path = staging / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"  manifest.json: {manifest['stats']['total_sigma_rules']} rules, "
          f"{manifest['stats']['mitre_techniques']} MITRE techniques")

    readme_path = staging / "README.md"
    readme_path.write_text(create_standalone_readme(), encoding="utf-8")

    # Create archives
    archives = []

    # .tar.gz
    tar_path = output_dir / f"{pack_dir_name}.tar.gz"
    print(f"\nCreating {tar_path.name}...")
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(staging, arcname=pack_dir_name)
    archives.append(tar_path)

    # .zip (optional)
    if create_zip:
        zip_path = output_dir / f"{pack_dir_name}.zip"
        print(f"Creating {zip_path.name}...")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(staging):
                for file in files:
                    file_path = Path(root) / file
                    arcname = str(file_path.relative_to(output_dir))
                    zf.write(file_path, arcname)
        archives.append(zip_path)

    # Cleanup staging
    shutil.rmtree(staging)

    # Print summary
    print(f"\n{'=' * 60}")
    print("BUILD COMPLETE")
    print(f"{'=' * 60}")
    for archive in archives:
        size_kb = archive.stat().st_size / 1024
        checksums = compute_checksums(archive)
        print(f"\n  {archive.name}")
        print(f"    Size:   {size_kb:.1f} KB")
        print(f"    SHA256: {checksums['sha256']}")

    print(f"\n  Rules:       {manifest['stats']['total_sigma_rules']}")
    print(f"  Categories:  {manifest['stats']['categories']}")
    print(f"  MITRE ATT&CK: {manifest['stats']['mitre_techniques']} techniques, "
          f"{manifest['stats']['mitre_tactics']} tactics")
    print(f"  SIEM targets: Splunk SPL, Sentinel KQL, Wazuh XML")
    print(f"{'=' * 60}\n")

    return archives


def _standalone_convert_cli() -> str:
    """Generate the standalone convert.py CLI script for the rule pack."""
    return '''#!/usr/bin/env python3
"""
NHI Detection Rule Pack — Standalone Sigma Conversion CLI

Convert Sigma YAML rules to Splunk SPL, Sentinel KQL, or Wazuh XML.

Requirements:
    pip install pySigma pySigma-backend-splunk pySigma-backend-microsoft365defender pyyaml

Usage:
    python convert.py --rules-dir ../rules --output-dir ../output --format all
    python convert.py --rules-dir ../rules --format splunk --category cloud-imds
    python convert.py --list-categories --rules-dir ../rules
"""

import argparse
import sys
import time
from pathlib import Path

# Add pipeline directory to path for sibling imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backends import ConversionStats, convert_sentinel, convert_splunk, convert_wazuh
from loader import CATEGORY_MAP, load_rules


VALID_FORMATS = ("wazuh", "splunk", "sentinel", "all")
VALID_CATEGORIES = tuple(CATEGORY_MAP.keys())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NHI Detection Rule Pack — Sigma Rule Converter",
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "rules",
        help="Input directory containing Sigma rules (default: ../rules/)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "output",
        help="Output directory (default: ../output/)",
    )
    parser.add_argument(
        "--wazuh-xml",
        type=Path,
        default=None,
        help="Existing Wazuh XML rules file for ID-based extraction",
    )
    parser.add_argument(
        "--format",
        choices=VALID_FORMATS,
        default="all",
        help="Output format (default: all)",
    )
    parser.add_argument(
        "--category",
        choices=VALID_CATEGORIES,
        default=None,
        help="Filter rules by category",
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        help="List available categories and exit",
    )

    args = parser.parse_args()

    if args.list_categories:
        print("\\nAvailable rule categories:")
        for dirname, display in CATEGORY_MAP.items():
            cat_path = args.rules_dir / dirname
            count = len(list(cat_path.glob("*.yml"))) if cat_path.is_dir() else 0
            print(f"  {dirname:25s} ({display}, {count} rules)")
        return 0

    start = time.monotonic()
    print(f"Loading Sigma rules from {args.rules_dir}...")
    load_result = load_rules(args.rules_dir, category_filter=args.category)
    print(f"  Loaded {len(load_result.standard_rules)} standard + "
          f"{len(load_result.correlation_raw)} correlation rules")

    if not load_result.standard_rules and not load_result.correlation_raw:
        print("No rules loaded. Check --rules-dir path.")
        return 1

    formats = ["wazuh", "splunk", "sentinel"] if args.format == "all" else [args.format]

    for fmt in formats:
        out = args.output_dir / fmt
        print(f"\\nConverting to {fmt.upper()} -> {out}")

        if fmt == "splunk":
            stats = convert_splunk(load_result.standard_rules, load_result.correlation_raw, out)
        elif fmt == "sentinel":
            stats = convert_sentinel(load_result.standard_rules, load_result.correlation_raw, out)
        elif fmt == "wazuh":
            if not args.wazuh_xml:
                print("  Skipping Wazuh (no --wazuh-xml provided)")
                continue
            stats = convert_wazuh(
                load_result.standard_rules, load_result.correlation_raw, args.wazuh_xml, out,
            )
        else:
            continue

        print(f"  {stats.successful}/{stats.total_attempted} rules converted")

    elapsed = time.monotonic() - start
    print(f"\\nDone in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def main() -> int:
    global VERSION

    parser = argparse.ArgumentParser(
        description="Build the NHI Detection Rule Pack archive",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DIST_DIR,
        help="Output directory for archives (default: dist/)",
    )
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Re-run sigma conversion before packaging",
    )
    parser.add_argument(
        "--format",
        choices=["tar", "zip", "both"],
        default="tar",
        help="Archive format(s) to create (default: tar)",
    )
    parser.add_argument(
        "--version",
        default=None,
        help=f"Override version (default: {VERSION})",
    )

    args = parser.parse_args()

    if args.version:
        VERSION = args.version

    create_zip = args.format in ("zip", "both")
    archives = build_archive(
        output_dir=args.output_dir,
        regenerate=args.regenerate,
        create_zip=create_zip,
    )

    return 0 if archives else 1


if __name__ == "__main__":
    sys.exit(main())
