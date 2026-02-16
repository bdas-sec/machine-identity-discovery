"""
Unit tests for the NHI Detection Rule Pack build pipeline.

Tests manifest generation, archive structure, and packaging integrity.
"""

import json
import tarfile
import pytest
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
SIGMA_RULES_DIR = PROJECT_ROOT / "sigma" / "rules"
SIGMA_OUTPUT_DIR = PROJECT_ROOT / "sigma" / "output"
BUILD_SCRIPT = PROJECT_ROOT / "scripts" / "build_rule_pack.py"


@pytest.mark.unit
class TestRulePackManifest:
    """Tests for manifest.json generation."""

    def test_build_script_exists(self):
        """Verify build_rule_pack.py exists."""
        assert BUILD_SCRIPT.exists(), "scripts/build_rule_pack.py not found"

    def test_sigma_rules_directory_exists(self):
        """Verify sigma/rules/ directory exists with categories."""
        assert SIGMA_RULES_DIR.exists(), "sigma/rules/ directory not found"
        categories = [d for d in SIGMA_RULES_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
        assert len(categories) >= 6, f"Expected at least 6 rule categories, found {len(categories)}"

    def test_all_categories_have_rules(self):
        """Verify each category directory contains YAML rules."""
        expected_categories = [
            "credential-discovery", "cloud-imds", "kubernetes",
            "cicd-pipeline", "secret-patterns", "ai-agent",
        ]
        for cat in expected_categories:
            cat_dir = SIGMA_RULES_DIR / cat
            assert cat_dir.exists(), f"Category directory missing: {cat}"
            rules = list(cat_dir.glob("*.yml"))
            assert len(rules) > 0, f"No rules in category: {cat}"

    def test_sigma_rules_have_required_fields(self):
        """Verify Sigma YAML rules have required fields."""
        import yaml

        required_fields = {"title", "id", "description", "detection", "level"}
        errors = []

        for yml_file in SIGMA_RULES_DIR.rglob("*.yml"):
            raw = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                continue
            # Correlation rules have different required fields
            if raw.get("type") == "correlation":
                continue
            missing = required_fields - set(raw.keys())
            if missing:
                errors.append(f"{yml_file.name}: missing {missing}")

        assert not errors, f"Rules with missing fields:\n" + "\n".join(errors[:10])

    def test_sigma_rules_have_mitre_tags(self):
        """Verify standard rules have MITRE ATT&CK tags."""
        import yaml

        rules_without_mitre = []

        for yml_file in SIGMA_RULES_DIR.rglob("*.yml"):
            raw = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("type") == "correlation":
                continue
            tags = raw.get("tags", [])
            has_mitre = any(str(t).startswith("attack.t") for t in tags)
            if not has_mitre:
                rules_without_mitre.append(yml_file.name)

        assert not rules_without_mitre, (
            f"Rules missing MITRE ATT&CK technique tags:\n"
            + "\n".join(rules_without_mitre[:10])
        )


@pytest.mark.unit
class TestPreConvertedOutputs:
    """Tests for pre-converted SIEM rule outputs."""

    def test_splunk_output_exists(self):
        """Verify Splunk SPL output exists."""
        spl_file = SIGMA_OUTPUT_DIR / "splunk" / "nhi_rules.spl"
        assert spl_file.exists(), "Pre-converted Splunk output not found"
        content = spl_file.read_text()
        assert len(content) > 100, "Splunk output file appears empty"

    def test_sentinel_output_exists(self):
        """Verify Sentinel KQL output exists."""
        kql_file = SIGMA_OUTPUT_DIR / "sentinel" / "nhi_rules.kql"
        assert kql_file.exists(), "Pre-converted Sentinel output not found"
        content = kql_file.read_text()
        assert len(content) > 100, "Sentinel output file appears empty"

    def test_wazuh_output_exists(self):
        """Verify Wazuh XML output exists."""
        xml_file = SIGMA_OUTPUT_DIR / "wazuh" / "nhi_rules.xml"
        assert xml_file.exists(), "Pre-converted Wazuh output not found"
        content = xml_file.read_text()
        assert len(content) > 100, "Wazuh output file appears empty"

    def test_correlation_stubs_exist(self):
        """Verify correlation stubs are generated for each SIEM."""
        for siem, ext in [("splunk", "spl"), ("sentinel", "kql"), ("wazuh", "xml")]:
            stub_file = SIGMA_OUTPUT_DIR / siem / f"nhi_correlation_stubs.{ext}"
            assert stub_file.exists(), f"Correlation stubs missing for {siem}"


@pytest.mark.unit
class TestBuildScript:
    """Tests for the build script module functions."""

    def test_generate_manifest(self):
        """Test manifest generation produces valid structure."""
        import sys
        sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
        from build_rule_pack import generate_manifest

        manifest = generate_manifest(SIGMA_RULES_DIR)

        assert manifest["name"] == "nhi-detection-rules"
        assert manifest["version"]
        assert manifest["schema_version"] == "1.0"
        assert manifest["stats"]["total_sigma_rules"] > 0
        assert manifest["stats"]["categories"] >= 6
        assert manifest["stats"]["mitre_techniques"] > 0
        assert len(manifest["mitre_attack"]["techniques"]) > 0
        assert len(manifest["mitre_attack"]["tactics"]) > 0
        assert "splunk" in manifest["siem_targets"]
        assert "sentinel" in manifest["siem_targets"]
        assert "wazuh" in manifest["siem_targets"]

    def test_manifest_categories_match_filesystem(self):
        """Verify manifest categories match actual directories."""
        import sys
        sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
        from build_rule_pack import generate_manifest

        manifest = generate_manifest(SIGMA_RULES_DIR)
        fs_categories = {
            d.name for d in SIGMA_RULES_DIR.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        }
        manifest_categories = set(manifest["categories"].keys())
        assert manifest_categories == fs_categories

    def test_build_archive(self, tmp_path):
        """Test archive creation produces valid .tar.gz."""
        import sys
        sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
        from build_rule_pack import build_archive

        archives = build_archive(output_dir=tmp_path, regenerate=False, create_zip=False)

        assert len(archives) == 1
        tar_path = archives[0]
        assert tar_path.exists()
        assert tar_path.suffix == ".gz"
        assert tar_path.stat().st_size > 0

        # Verify archive contents
        with tarfile.open(tar_path, "r:gz") as tar:
            names = tar.getnames()
            pack_prefix = names[0].split("/")[0]  # e.g. "nhi-detection-rules-0.1.0"

            assert f"{pack_prefix}/manifest.json" in names
            assert f"{pack_prefix}/README.md" in names

            # Check rules directory exists
            rule_entries = [n for n in names if "/rules/" in n and n.endswith(".yml")]
            assert len(rule_entries) > 0, "No Sigma YAML rules in archive"

            # Check converted outputs
            assert any("/converted/splunk/" in n for n in names), "No Splunk outputs"
            assert any("/converted/sentinel/" in n for n in names), "No Sentinel outputs"
            assert any("/converted/wazuh/" in n for n in names), "No Wazuh outputs"

            # Check pipeline
            assert any("/pipeline/__init__.py" in n for n in names), "Pipeline __init__.py missing"
            assert any("/pipeline/convert.py" in n for n in names), "Standalone CLI missing"
            assert any("/pipeline/backends.py" in n for n in names), "Pipeline backends missing"

    def test_archive_manifest_valid_json(self, tmp_path):
        """Test that manifest.json in archive is valid JSON."""
        import sys
        sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
        from build_rule_pack import build_archive

        archives = build_archive(output_dir=tmp_path, regenerate=False, create_zip=False)
        tar_path = archives[0]

        with tarfile.open(tar_path, "r:gz") as tar:
            names = tar.getnames()
            manifest_name = [n for n in names if n.endswith("manifest.json")][0]
            f = tar.extractfile(manifest_name)
            manifest = json.loads(f.read())

        assert manifest["name"] == "nhi-detection-rules"
        assert manifest["stats"]["total_sigma_rules"] > 60
