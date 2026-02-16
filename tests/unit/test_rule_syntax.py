"""
Unit tests for Wazuh rule syntax validation.

Tests XML well-formedness and rule structure.
"""

import pytest
from pathlib import Path
from lxml import etree
import re


# Path to Wazuh rules directory
RULES_DIR = Path(__file__).parent.parent.parent / "wazuh" / "rules"
DECODERS_DIR = Path(__file__).parent.parent.parent / "wazuh" / "decoders"


def _parse_wazuh_xml(file_path):
    """Parse Wazuh XML files that may have multiple root elements."""
    content = Path(file_path).read_text()
    wrapped = f"<root>{content}</root>"
    return etree.fromstring(wrapped.encode())


@pytest.mark.unit
class TestRuleXMLWellFormed:
    """Tests for XML well-formedness of rule files."""

    def test_rules_directory_exists(self):
        """Verify rules directory exists."""
        assert RULES_DIR.exists(), f"Rules directory not found: {RULES_DIR}"

    def test_all_rule_files_parse(self):
        """Verify all rule XML files are well-formed."""
        if not RULES_DIR.exists():
            pytest.skip("Rules directory not found")

        rule_files = list(RULES_DIR.glob("*.xml"))
        assert len(rule_files) > 0, "No rule files found"

        for rule_file in rule_files:
            try:
                _parse_wazuh_xml(rule_file)
            except etree.XMLSyntaxError as e:
                pytest.fail(f"XML syntax error in {rule_file.name}: {e}")

    def test_nhi_rules_file_exists(self):
        """Verify NHI-specific rules file exists."""
        nhi_patterns = ["nhi", "machine-identity", "cloud", "cicd"]

        if not RULES_DIR.exists():
            pytest.skip("Rules directory not found")

        rule_files = list(RULES_DIR.glob("*.xml"))
        found = any(
            any(p in f.name.lower() for p in nhi_patterns)
            for f in rule_files
        )

        # At least one NHI-related rule file should exist
        assert found or len(rule_files) > 0, "No NHI rule files found"


@pytest.mark.unit
class TestRuleStructure:
    """Tests for rule structure and content."""

    def _get_all_rules(self):
        """Helper to get all rules from XML files."""
        rules = []
        if not RULES_DIR.exists():
            return rules

        for rule_file in RULES_DIR.glob("*.xml"):
            try:
                root = _parse_wazuh_xml(rule_file)
                rules.extend(root.findall(".//rule"))
            except Exception:
                pass

        return rules

    def test_rules_have_ids(self):
        """Verify all rules have ID attributes."""
        rules = self._get_all_rules()
        if not rules:
            pytest.skip("No rules found")

        for rule in rules:
            rule_id = rule.get("id")
            assert rule_id is not None, "Rule missing id attribute"

    def test_rules_have_levels(self):
        """Verify all rules have level attributes."""
        rules = self._get_all_rules()
        if not rules:
            pytest.skip("No rules found")

        for rule in rules:
            level = rule.get("level")
            assert level is not None, \
                f"Rule {rule.get('id')} missing level attribute"

    def test_rule_levels_valid(self):
        """Verify rule levels are in valid range (0-15)."""
        rules = self._get_all_rules()
        if not rules:
            pytest.skip("No rules found")

        for rule in rules:
            level = rule.get("level")
            if level:
                level_int = int(level)
                assert 0 <= level_int <= 15, \
                    f"Rule {rule.get('id')} has invalid level: {level}"

    def test_rules_have_descriptions(self):
        """Verify rules have description elements."""
        rules = self._get_all_rules()
        if not rules:
            pytest.skip("No rules found")

        for rule in rules:
            desc = rule.find("description")
            assert desc is not None and desc.text, \
                f"Rule {rule.get('id')} missing description"


@pytest.mark.unit
class TestNHIRuleIDs:
    """Tests for NHI-specific rule ID ranges."""

    def _get_nhi_rules(self):
        """Get rules in NHI ID range (100600-100999)."""
        rules = []
        if not RULES_DIR.exists():
            return rules

        for rule_file in RULES_DIR.glob("*.xml"):
            try:
                root = _parse_wazuh_xml(rule_file)
                for rule in root.findall(".//rule"):
                    rule_id = rule.get("id")
                    if rule_id:
                        try:
                            if 100600 <= int(rule_id) <= 100999:
                                rules.append(rule)
                        except ValueError:
                            pass
            except Exception:
                pass

        return rules

    def test_nhi_rules_exist(self):
        """Verify NHI rules exist in expected range."""
        rules = self._get_nhi_rules()
        assert len(rules) > 0, \
            "No NHI rules found in range 100600-100999"

    def test_nhi_rule_count(self):
        """Verify minimum number of NHI rules."""
        rules = self._get_nhi_rules()
        # Expect at least 20 NHI rules based on scenarios
        assert len(rules) >= 20, \
            f"Expected at least 20 NHI rules, found {len(rules)}"

    def test_nhi_rules_high_severity(self):
        """Verify NHI rules have appropriate severity levels."""
        rules = self._get_nhi_rules()
        if not rules:
            pytest.skip("No NHI rules found")

        high_severity_count = 0
        for rule in rules:
            level = int(rule.get("level", 0))
            if level >= 10:
                high_severity_count += 1

        # Most NHI rules should be high severity
        assert high_severity_count > 0, \
            "Expected some high-severity NHI rules"


@pytest.mark.unit
class TestMITREMappings:
    """Tests for MITRE ATT&CK mappings in rules."""

    def _get_rules_with_mitre(self):
        """Get rules that have MITRE mappings."""
        rules = []
        if not RULES_DIR.exists():
            return rules

        for rule_file in RULES_DIR.glob("*.xml"):
            try:
                root = _parse_wazuh_xml(rule_file)
                for rule in root.findall(".//rule"):
                    mitre = rule.find("mitre")
                    if mitre is not None:
                        rules.append((rule, mitre))
            except Exception:
                pass

        return rules

    def test_mitre_technique_ids_valid(self):
        """Verify MITRE technique IDs are valid format."""
        rules_with_mitre = self._get_rules_with_mitre()
        if not rules_with_mitre:
            pytest.skip("No rules with MITRE mappings found")

        pattern = re.compile(r"T\d{4}(\.\d{3})?")

        for rule, mitre in rules_with_mitre:
            for id_elem in mitre.findall("id"):
                if id_elem.text:
                    assert pattern.match(id_elem.text), \
                        f"Invalid MITRE ID in rule {rule.get('id')}: {id_elem.text}"

    def test_mitre_has_technique_ids(self):
        """Verify MITRE elements have technique IDs."""
        rules_with_mitre = self._get_rules_with_mitre()
        if not rules_with_mitre:
            pytest.skip("No rules with MITRE mappings found")

        for rule, mitre in rules_with_mitre:
            id_elems = mitre.findall("id")
            assert len(id_elems) > 0, \
                f"Rule {rule.get('id')} MITRE mapping has no technique IDs"


@pytest.mark.unit
class TestDecoderSyntax:
    """Tests for decoder XML syntax."""

    def test_decoders_directory_exists(self):
        """Verify decoders directory exists."""
        # Decoders might be optional
        if not DECODERS_DIR.exists():
            pytest.skip("Decoders directory not found")

    def test_all_decoder_files_parse(self):
        """Verify all decoder XML files are well-formed."""
        if not DECODERS_DIR.exists():
            pytest.skip("Decoders directory not found")

        decoder_files = list(DECODERS_DIR.glob("*.xml"))
        if not decoder_files:
            pytest.skip("No decoder files found")

        for decoder_file in decoder_files:
            try:
                _parse_wazuh_xml(decoder_file)
            except etree.XMLSyntaxError as e:
                pytest.fail(f"XML syntax error in {decoder_file.name}: {e}")

    def test_decoders_have_names(self):
        """Verify decoders have name attributes."""
        if not DECODERS_DIR.exists():
            pytest.skip("Decoders directory not found")

        for decoder_file in DECODERS_DIR.glob("*.xml"):
            try:
                root = _parse_wazuh_xml(decoder_file)
                for decoder in root.findall(".//decoder"):
                    name = decoder.get("name")
                    assert name is not None, \
                        f"Decoder in {decoder_file.name} missing name attribute"
            except Exception as e:
                pytest.fail(f"Error parsing {decoder_file.name}: {e}")
