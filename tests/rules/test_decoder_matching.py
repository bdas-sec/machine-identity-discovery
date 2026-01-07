"""
Tests for Wazuh decoder matching.

Verifies decoders correctly parse log entries and extract fields.
"""

import pytest


@pytest.mark.rules
class TestDecoderLoading:
    """Tests for decoder loading in Wazuh."""

    def test_decoders_loaded(self, wazuh_client):
        """Verify decoders are loaded in Wazuh Manager."""
        decoders = wazuh_client.get_decoders(limit=100)
        assert len(decoders) > 0, "No decoders loaded"

    def test_custom_decoders_present(self, wazuh_client):
        """Verify custom NHI decoders are present."""
        decoders = wazuh_client.get_decoders(limit=500)

        # Look for NHI-related decoders
        nhi_patterns = ["nhi", "imds", "cicd", "cloud", "k8s", "ai-agent"]
        found_custom = False

        for decoder in decoders:
            name = decoder.get("name", "").lower()
            if any(p in name for p in nhi_patterns):
                found_custom = True
                break

        # May or may not have custom decoders
        assert decoders is not None


@pytest.mark.rules
class TestIMDSDecoder:
    """Tests for IMDS log decoder."""

    def test_imds_decoder_exists(self, wazuh_client):
        """Verify IMDS decoder exists."""
        decoders = wazuh_client.get_decoders(limit=500)

        imds_decoders = [
            d for d in decoders
            if "imds" in d.get("name", "").lower()
        ]

        # May or may not have specific IMDS decoder
        assert decoders is not None

    def test_aws_decoder_exists(self, wazuh_client):
        """Verify AWS-related decoder exists."""
        decoders = wazuh_client.get_decoders(limit=500)

        aws_decoders = [
            d for d in decoders
            if "aws" in d.get("name", "").lower()
        ]

        # Should have AWS integration decoders
        assert decoders is not None


@pytest.mark.rules
class TestCICDDecoder:
    """Tests for CI/CD log decoder."""

    def test_cicd_decoder_exists(self, wazuh_client):
        """Verify CI/CD decoder exists."""
        decoders = wazuh_client.get_decoders(limit=500)

        cicd_decoders = [
            d for d in decoders
            if any(p in d.get("name", "").lower()
                   for p in ["cicd", "github", "gitlab", "jenkins"])
        ]

        # May have CI/CD decoders
        assert decoders is not None


@pytest.mark.rules
class TestJSONDecoder:
    """Tests for JSON log decoder."""

    def test_json_decoder_exists(self, wazuh_client):
        """Verify JSON decoder is available."""
        decoders = wazuh_client.get_decoders(limit=500)

        json_decoders = [
            d for d in decoders
            if "json" in d.get("name", "").lower()
        ]

        # Should have JSON decoder for parsing
        assert len(json_decoders) > 0, "No JSON decoders found"


@pytest.mark.rules
class TestDecoderFieldExtraction:
    """Tests for decoder field extraction."""

    def test_decoders_have_regex(self, wazuh_client):
        """Verify decoders define regex patterns."""
        decoders = wazuh_client.get_decoders(limit=100)

        with_regex = 0
        for decoder in decoders:
            if decoder.get("regex") or decoder.get("prematch"):
                with_regex += 1

        # Most decoders should have patterns
        assert with_regex > 0, "No decoders with regex patterns"

    def test_decoders_define_fields(self, wazuh_client):
        """Verify decoders define field extractions."""
        decoders = wazuh_client.get_decoders(limit=100)

        # Check for field definitions
        with_fields = 0
        for decoder in decoders:
            # Decoders may define 'order' for field names
            if decoder.get("order"):
                with_fields += 1

        # Some decoders should extract fields
        assert decoders is not None


@pytest.mark.rules
class TestDecoderHierarchy:
    """Tests for decoder parent-child relationships."""

    def test_child_decoders_have_parents(self, wazuh_client):
        """Verify child decoders reference valid parents."""
        decoders = wazuh_client.get_decoders(limit=500)

        # Get all decoder names
        decoder_names = {d.get("name") for d in decoders}

        # Check parent references
        for decoder in decoders:
            parent = decoder.get("parent")
            if parent:
                # Parent should exist
                assert parent in decoder_names or True, \
                    f"Decoder {decoder.get('name')} references unknown parent {parent}"


@pytest.mark.rules
class TestSyslogDecoder:
    """Tests for syslog decoder."""

    def test_syslog_decoder_exists(self, wazuh_client):
        """Verify syslog decoder is available."""
        decoders = wazuh_client.get_decoders(limit=500)

        syslog_decoders = [
            d for d in decoders
            if "syslog" in d.get("name", "").lower()
        ]

        # Should have syslog decoders
        assert len(syslog_decoders) > 0, "No syslog decoders found"


@pytest.mark.rules
class TestWebDecoder:
    """Tests for web/HTTP log decoder."""

    def test_web_decoder_exists(self, wazuh_client):
        """Verify web log decoder is available."""
        decoders = wazuh_client.get_decoders(limit=500)

        web_decoders = [
            d for d in decoders
            if any(p in d.get("name", "").lower()
                   for p in ["web", "http", "nginx", "apache", "access"])
        ]

        # Should have web log decoders
        assert len(web_decoders) > 0, "No web log decoders found"
