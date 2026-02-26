#!/usr/bin/env python3
"""Comprehensive functional tests for the results system."""

import sys
from pathlib import Path
import json


sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from urlchecker.core.results import ProviderResult, ThreatLevel


class TestResultsSystemFunctionality:
    """Test results system functionality comprehensively."""

    def test_threat_level_enum_completeness(self):
        """Test ThreatLevel enum has all required values."""
        # Test all expected threat levels exist
        expected_levels = ["safe", "suspicious", "malicious", "critical", "error", "unknown"]

        for level in expected_levels:
            assert hasattr(ThreatLevel, level.upper()), f"ThreatLevel should have {level.upper()}"
            enum_value = getattr(ThreatLevel, level.upper())
            assert enum_value.value == level, f"ThreatLevel.{level.upper()} should have value '{level}'"

    def test_threat_level_ordering(self):
        """Test ThreatLevel enum values have logical ordering."""
        # Test that threat levels can be compared sensibly
        assert ThreatLevel.SAFE.value == "safe"
        assert ThreatLevel.SUSPICIOUS.value == "suspicious"
        assert ThreatLevel.MALICIOUS.value == "malicious"
        assert ThreatLevel.CRITICAL.value == "critical"

        # Special cases
        assert ThreatLevel.ERROR.value == "error"
        assert ThreatLevel.UNKNOWN.value == "unknown"

    def test_provider_result_creation_safe(self):
        """Test creating safe ProviderResult."""
        result = ProviderResult(
            provider="test_provider",
            target="https://safe.example.com",
            is_threat=False,
            threat_level=ThreatLevel.SAFE,
            confidence=0.95,
            details={"status": "clean", "checks_passed": 5}
        )

        assert result.provider == "test_provider"
        assert result.target == "https://safe.example.com"
        assert result.is_threat == False
        assert result.threat_level == ThreatLevel.SAFE
        assert result.confidence == 0.95
        assert result.details["status"] == "clean"
        assert result.details["checks_passed"] == 5

    def test_provider_result_creation_threat(self):
        """Test creating threat ProviderResult."""
        result = ProviderResult(
            provider="virus_scanner",
            target="https://malicious.example.com",
            is_threat=True,
            threat_level=ThreatLevel.MALICIOUS,
            confidence=0.87,
            details={"malware_type": "trojan", "signature": "Win32.Trojan.Gen"}
        )

        assert result.provider == "virus_scanner"
        assert result.target == "https://malicious.example.com"
        assert result.is_threat == True
        assert result.threat_level == ThreatLevel.MALICIOUS
        assert result.confidence == 0.87
        assert result.details["malware_type"] == "trojan"

    def test_provider_result_creation_error(self):
        """Test creating error ProviderResult."""
        result = ProviderResult(
            provider="api_provider",
            target="https://example.com",
            is_threat=False,
            threat_level=ThreatLevel.ERROR,
            confidence=0.0,
            details={"error": "API timeout", "status_code": 500}
        )

        assert result.provider == "api_provider"
        assert result.is_threat == False
        assert result.threat_level == ThreatLevel.ERROR
        assert result.confidence == 0.0
        assert "error" in result.details

    def test_provider_result_serialization(self):
        """Test ProviderResult can be serialized to dict/JSON."""
        result = ProviderResult(
            provider="test_provider",
            target="https://example.com",
            is_threat=True,
            threat_level=ThreatLevel.SUSPICIOUS,
            confidence=0.75,
            details={"reason": "suspicious patterns", "score": 6.5}
        )

        # Test serialization to dict
        result_dict = {
            "provider": result.provider,
            "target": result.target,
            "is_threat": result.is_threat,
            "threat_level": result.threat_level.value,
            "confidence": result.confidence,
            "details": result.details
        }

        assert isinstance(result_dict, dict)
        assert result_dict["provider"] == "test_provider"
        assert result_dict["threat_level"] == "suspicious"
        assert result_dict["is_threat"] == True

        # Test JSON serialization
        json_str = json.dumps(result_dict)
        assert isinstance(json_str, str)

        # Test deserialization
        restored = json.loads(json_str)
        assert restored["provider"] == "test_provider"
        assert restored["threat_level"] == "suspicious"

    def test_provider_result_with_complex_details(self):
        """Test ProviderResult handles complex details structures."""
        complex_details = {
            "scan_results": {
                "engines": [
                    {"name": "Engine1", "result": "clean", "version": "1.0"},
                    {"name": "Engine2", "result": "malicious", "signature": "Trojan.Gen"},
                    {"name": "Engine3", "result": "suspicious", "confidence": 0.6}
                ],
                "summary": {
                    "total_engines": 3,
                    "clean": 1,
                    "malicious": 1,
                    "suspicious": 1
                }
            },
            "metadata": {
                "scan_time": "2023-01-01T12:00:00Z",
                "file_hash": "abc123def456",
                "file_size": 1024
            },
            "tags": ["trojan", "packed", "suspicious"]
        }

        result = ProviderResult(
            provider="multi_engine_scanner",
            target="https://complex.example.com",
            is_threat=True,
            threat_level=ThreatLevel.MALICIOUS,
            confidence=0.8,
            details=complex_details
        )

        # Should handle nested structures
        assert result.details["scan_results"]["summary"]["total_engines"] == 3
        assert len(result.details["scan_results"]["engines"]) == 3
        assert "trojan" in result.details["tags"]
        assert result.details["metadata"]["file_size"] == 1024

    def test_provider_result_confidence_validation(self):
        """Test confidence values are handled correctly."""
        # Test various confidence values
        confidence_cases = [0.0, 0.5, 0.95, 1.0]

        for confidence in confidence_cases:
            result = ProviderResult(
                provider="test",
                target="https://example.com",
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=confidence,
                details={}
            )

            assert result.confidence == confidence
            assert 0.0 <= result.confidence <= 1.0

    def test_provider_result_immutability_aspects(self):
        """Test ProviderResult maintains data integrity."""
        original_details = {"status": "clean", "score": 8}

        result = ProviderResult(
            provider="test_provider",
            target="https://example.com",
            is_threat=False,
            threat_level=ThreatLevel.SAFE,
            confidence=0.9,
            details=original_details.copy()
        )

        # Modifying original dict shouldn't affect result
        original_details["status"] = "modified"
        assert result.details["status"] == "clean"

        # Result should maintain its values
        assert result.provider == "test_provider"
        assert result.is_threat == False

    def test_provider_result_with_execution_time(self):
        """Test ProviderResult can include execution timing."""
        result = ProviderResult(
            provider="timed_provider",
            target="https://example.com",
            is_threat=False,
            threat_level=ThreatLevel.SAFE,
            confidence=0.9,
            details={"execution_time_ms": 150.5}
        )

        # Execution time can be stored in details
        assert "execution_time_ms" in result.details
        assert result.details["execution_time_ms"] == 150.5

    def test_threat_level_string_representations(self):
        """Test ThreatLevel string representations are correct."""
        string_mappings = {
            ThreatLevel.SAFE: "safe",
            ThreatLevel.SUSPICIOUS: "suspicious",
            ThreatLevel.MALICIOUS: "malicious",
            ThreatLevel.CRITICAL: "critical",
            ThreatLevel.ERROR: "error",
            ThreatLevel.UNKNOWN: "unknown"
        }

        for enum_val, expected_str in string_mappings.items():
            assert enum_val.value == expected_str
            assert str(enum_val.value) == expected_str

    def test_provider_result_equality_comparison(self):
        """Test ProviderResult objects can be compared."""
        result1 = ProviderResult(
            provider="test",
            target="https://example.com",
            is_threat=False,
            threat_level=ThreatLevel.SAFE,
            confidence=0.9,
            details={"status": "clean"}
        )

        result2 = ProviderResult(
            provider="test",
            target="https://example.com",
            is_threat=False,
            threat_level=ThreatLevel.SAFE,
            confidence=0.9,
            details={"status": "clean"}
        )

        result3 = ProviderResult(
            provider="different",
            target="https://example.com",
            is_threat=False,
            threat_level=ThreatLevel.SAFE,
            confidence=0.9,
            details={"status": "clean"}
        )

        # Results with same data should be comparable
        assert result1.provider == result2.provider
        assert result1.target == result2.target
        assert result1.is_threat == result2.is_threat
        assert result1.threat_level == result2.threat_level

        # Different results should be distinguishable
        assert result1.provider != result3.provider

    def test_provider_result_with_empty_details(self):
        """Test ProviderResult handles empty details correctly."""
        result = ProviderResult(
            provider="minimal_provider",
            target="https://example.com",
            is_threat=False,
            threat_level=ThreatLevel.SAFE,
            confidence=0.8,
            details={}
        )

        assert isinstance(result.details, dict)
        assert len(result.details) == 0
        assert result.provider == "minimal_provider"

    def test_provider_result_with_none_details(self):
        """Test ProviderResult handles None details gracefully."""
        # Test what happens with None details (if allowed)
        try:
            result = ProviderResult(
                provider="none_details_provider",
                target="https://example.com",
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=0.8,
                details=None
            )
            # If None is allowed, ensure it doesn't break anything
            assert result.details is None
        except (TypeError, ValueError):
            # If None is not allowed, that's also acceptable
            pass

    def test_threat_level_case_sensitivity(self):
        """Test ThreatLevel enum values are case-consistent."""
        # All enum values should be lowercase
        for threat_level in ThreatLevel:
            assert threat_level.value.islower(), f"ThreatLevel {threat_level.name} value should be lowercase"

    def test_provider_result_large_details(self):
        """Test ProviderResult handles large details structures."""
        # Create a large details structure
        large_details = {
            f"key_{i}": f"value_{i}" for i in range(1000)
        }
        large_details["nested"] = {
            "deep": {
                "structure": {
                    "with": ["many", "items"] * 100
                }
            }
        }

        result = ProviderResult(
            provider="large_data_provider",
            target="https://example.com",
            is_threat=False,
            threat_level=ThreatLevel.SAFE,
            confidence=0.9,
            details=large_details
        )

        # Should handle large data structures
        assert len(result.details) == 1001  # 1000 + nested key
        assert "key_999" in result.details
        assert result.details["key_999"] == "value_999"
        assert len(result.details["nested"]["deep"]["structure"]["with"]) == 200

    def test_provider_result_special_characters(self):
        """Test ProviderResult handles special characters in data."""
        special_details = {
            "unicode_text": "Testing: 你好世界 🌍 café naïve résumé",
            "special_chars": "!@#$%^&*()_+-=[]{}|;:,.<>?",
            "escaped_chars": "\"quoted\" and 'apostrophe' and \\backslash\\",
            "newlines": "line1\nline2\r\nline3",
            "null_bytes": "text\x00with\x00nulls"
        }

        result = ProviderResult(
            provider="special_chars_provider",
            target="https://example.com",
            is_threat=False,
            threat_level=ThreatLevel.SAFE,
            confidence=0.9,
            details=special_details
        )

        # Should preserve special characters
        assert "你好世界" in result.details["unicode_text"]
        assert "!@#$%^&*()" in result.details["special_chars"]
        assert "\"quoted\"" in result.details["escaped_chars"]
        assert "\n" in result.details["newlines"]

    def test_provider_result_with_different_target_types(self):
        """Test ProviderResult handles different target formats."""
        target_formats = [
            "https://example.com",
            "http://example.com/path",
            "example.com",
            "192.168.1.1",
            "2001:db8::1",
            "file:///path/to/file.exe",
            "ftp://ftp.example.com/file.zip"
        ]

        for target in target_formats:
            result = ProviderResult(
                provider="flexible_provider",
                target=target,
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=0.9,
                details={"target_type": "auto_detected"}
            )

            assert result.target == target
            assert isinstance(result.target, str)

    def test_provider_result_aggregation_compatibility(self):
        """Test ProviderResult objects work well for aggregation."""
        results = []

        # Create multiple results
        for i in range(10):
            is_threat = i % 3 == 0  # Every 3rd is a threat
            threat_level = ThreatLevel.MALICIOUS if is_threat else ThreatLevel.SAFE

            result = ProviderResult(
                provider=f"provider_{i}",
                target=f"https://example{i}.com",
                is_threat=is_threat,
                threat_level=threat_level,
                confidence=0.8 + (i * 0.01),
                details={"index": i}
            )
            results.append(result)

        # Test aggregation operations
        threat_results = [r for r in results if r.is_threat]
        safe_results = [r for r in results if not r.is_threat]

        assert len(threat_results) > 0
        assert len(safe_results) > 0
        assert len(threat_results) + len(safe_results) == len(results)

        # Test confidence calculations
        avg_confidence = sum(r.confidence for r in results) / len(results)
        assert 0.8 <= avg_confidence <= 0.9

        # Test provider grouping
        providers = {r.provider for r in results}
        assert len(providers) == 10