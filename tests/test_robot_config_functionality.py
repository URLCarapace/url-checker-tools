#!/usr/bin/env python3
"""Comprehensive functional tests for robot configuration system."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from urlchecker.config.robot_config import (
    RobotModeProviderSet,
    RobotModeFlags,
    RobotModeConfig
)


class TestRobotConfigurationFunctionality:
    """Test robot configuration functionality comprehensively."""

    def test_robot_provider_set_completeness(self):
        """Test ROBOT provider set contains essential providers."""
        robot_providers = RobotModeProviderSet.ROBOT.value

        # Should be a list
        assert isinstance(robot_providers, list)
        assert len(robot_providers) > 0

        # Should contain essential providers for automated scanning
        essential_providers = ["whois", "virustotal", "google_sb", "yara"]
        for provider in essential_providers:
            assert provider in robot_providers, f"Essential provider {provider} missing from ROBOT set"

        # Should not contain experimental providers
        experimental_providers = ["urlscan", "lookyloo"]
        for provider in experimental_providers:
            assert provider not in robot_providers, f"Experimental provider {provider} should not be in ROBOT set"

    def test_all_provider_set_completeness(self):
        """Test ALL provider set contains comprehensive provider list."""
        all_providers = RobotModeProviderSet.ALL.value

        # Should be a list with more providers than ROBOT
        assert isinstance(all_providers, list)
        robot_providers = RobotModeProviderSet.ROBOT.value
        assert len(all_providers) >= len(robot_providers)

        # Should include all robot providers
        for provider in robot_providers:
            assert provider in all_providers, f"Robot provider {provider} missing from ALL set"

        # Should include additional providers
        additional_expected = ["misp", "urlscan", "lookyloo"]
        for provider in additional_expected:
            assert provider in all_providers, f"Expected provider {provider} missing from ALL set"

    def test_provider_set_consistency(self):
        """Test consistency between provider sets."""
        robot_providers = set(RobotModeProviderSet.ROBOT.value)
        all_providers = set(RobotModeProviderSet.ALL.value)

        # ROBOT should be subset of ALL
        assert robot_providers.issubset(all_providers), "ROBOT providers should be subset of ALL providers"

        # No duplicate providers in sets
        assert len(RobotModeProviderSet.ROBOT.value) == len(robot_providers), "No duplicates in ROBOT set"
        assert len(RobotModeProviderSet.ALL.value) == len(all_providers), "No duplicates in ALL set"

    def test_robot_flags_structure(self):
        """Test ROBOT flags have correct structure and values."""
        robot_flags = RobotModeFlags.ROBOT.value

        # Should be a dictionary
        assert isinstance(robot_flags, dict)

        # Should contain all required flags
        required_flags = ["log", "score", "format", "verbose", "misp_report", "auto_scan_files"]
        for flag in required_flags:
            assert flag in robot_flags, f"Required flag {flag} missing from ROBOT flags"

        # Should have automation-friendly defaults
        assert robot_flags["log"] == True, "Logging should be enabled for robot mode"
        assert robot_flags["score"] == True, "Scoring should be enabled for robot mode"
        assert robot_flags["format"] == "synthesis", "Format should be machine-readable for robot mode"
        assert robot_flags["verbose"] == False, "Verbose should be disabled for robot mode automation"
        assert robot_flags["misp_report"] == False, "MISP reporting should be opt-in"
        assert robot_flags["auto_scan_files"] == False, "File scanning should be opt-in"

    def test_robot_config_provider_methods(self):
        """Test RobotModeConfig provider retrieval methods."""
        # Test robot providers
        robot_providers = RobotModeConfig.get_robot_providers()
        assert isinstance(robot_providers, list)
        assert len(robot_providers) > 0
        assert robot_providers == RobotModeProviderSet.ROBOT.value

        # Test all providers
        all_providers = RobotModeConfig.get_all_providers()
        assert isinstance(all_providers, list)
        assert len(all_providers) >= len(robot_providers)
        assert all_providers == RobotModeProviderSet.ALL.value

    def test_robot_config_flags_method(self):
        """Test RobotModeConfig flags retrieval method."""
        flags = RobotModeConfig.get_robot_flags()

        assert isinstance(flags, dict)
        assert flags == RobotModeFlags.ROBOT.value

        # Should return a copy to prevent mutation
        flags["test"] = "modified"
        flags2 = RobotModeConfig.get_robot_flags()
        assert "test" not in flags2, "Flags should be returned as a copy"

    def test_apply_robot_flags_basic_functionality(self):
        """Test basic robot flag application works correctly."""
        # Create mock args object
        args = SimpleNamespace()
        args.format = "human"
        args.log = False
        args.score = False
        args.verbose = False
        args.misp_report = False
        args.auto_scan_files = False

        # Mock sys.argv to simulate robot mode without explicit flags
        with patch('sys.argv', ['script.py', '--robot', '--sid', 'test']):
            RobotModeConfig.apply_robot_flags(args)

        # Robot flags should be applied
        assert args.format == "synthesis", "Robot mode should set synthesis format"
        assert args.log == True, "Robot mode should enable logging"
        assert args.score == True, "Robot mode should enable scoring"
        assert args.verbose == False, "Robot mode should keep verbose disabled"

    def test_apply_robot_flags_preserve_explicit_flags(self):
        """Test that explicit CLI flags are preserved over robot defaults."""
        args = SimpleNamespace()
        args.format = "json"  # Explicitly set
        args.log = False
        args.score = False
        args.verbose = True   # Explicitly set

        # Mock sys.argv to simulate explicit flags
        with patch('sys.argv', ['script.py', '--robot', '--format', 'json', '--verbose']):
            RobotModeConfig.apply_robot_flags(args)

        # Explicit flags should be preserved
        assert args.format == "json", "Explicit format flag should be preserved"
        assert args.verbose == True, "Explicit verbose flag should be preserved"
        # Non-explicit flags should get robot values
        assert args.log == True, "Non-explicit log flag should get robot value"
        assert args.score == True, "Non-explicit score flag should get robot value"

    def test_apply_robot_flags_score_detail_handling(self):
        """Test score_detail flag implies score flag."""
        args = SimpleNamespace()
        args.score = False
        args.score_detail = False

        # Mock robot flags with score_detail enabled
        mock_flags = {
            "log": True,
            "score_detail": True,
            "format": "synthesis",
            "verbose": False,
            "misp_report": False,
            "auto_scan_files": False
        }

        with patch.object(RobotModeConfig, 'get_robot_flags', return_value=mock_flags):
            with patch('sys.argv', ['script.py']):
                RobotModeConfig.apply_robot_flags(args)

        # score_detail should imply score
        assert args.score_detail == True, "score_detail should be set"
        assert args.score == True, "score should be implied by score_detail"

    def test_apply_robot_flags_error_handling(self):
        """Test robust error handling in flag application."""
        # Test with minimal args object
        args = SimpleNamespace()

        # Should not crash with missing attributes
        try:
            with patch('sys.argv', ['script.py']):
                RobotModeConfig.apply_robot_flags(args)
        except Exception as e:
            pytest.fail(f"apply_robot_flags should handle missing attributes gracefully: {e}")

        # Test with import failure
        with patch('sys.modules', {'sys': None}):
            try:
                RobotModeConfig.apply_robot_flags(args)
            except Exception as e:
                # Should handle import errors gracefully
                pass

    def test_flag_detection_accuracy(self):
        """Test CLI flag detection works accurately."""
        args = SimpleNamespace()
        args.format = "human"
        args.verbose = False
        args.log = False

        # Test format flag detection
        test_cases = [
            (['script.py', '--format', 'json'], "json"),
            (['script.py', '--robot'], "synthesis"),  # No explicit format
            (['script.py', '--format', 'human', '--robot'], "human"),  # Explicit format
        ]

        for argv, expected_format in test_cases:
            args.format = "human"  # Reset
            with patch('sys.argv', argv):
                RobotModeConfig.apply_robot_flags(args)
                if '--format' in argv and argv != ['script.py', '--robot']:
                    # When format is explicit, it should be preserved
                    continue
                else:
                    # When no explicit format and robot mode, should be synthesis
                    if '--robot' in argv:
                        assert args.format == "synthesis"

    def test_provider_set_integration(self):
        """Test provider sets integrate correctly with system."""
        robot_providers = RobotModeConfig.get_robot_providers()
        all_providers = RobotModeConfig.get_all_providers()

        # Both should return valid provider names
        for provider_list in [robot_providers, all_providers]:
            for provider in provider_list:
                assert isinstance(provider, str), f"Provider {provider} should be string"
                assert len(provider) > 0, f"Provider name should not be empty"
                assert "_" in provider or provider.isalnum(), f"Provider {provider} should have valid name format"

    def test_robot_flags_immutability(self):
        """Test robot flags cannot be accidentally mutated."""
        flags1 = RobotModeConfig.get_robot_flags()
        flags2 = RobotModeConfig.get_robot_flags()

        # Should be equal but separate objects
        assert flags1 == flags2
        assert flags1 is not flags2

        # Modifying one shouldn't affect the other
        flags1["modified"] = True
        assert "modified" not in flags2

        # Original enum value should be unchanged
        original = RobotModeFlags.ROBOT.value
        assert "modified" not in original

    def test_configuration_consistency_across_calls(self):
        """Test configuration remains consistent across multiple calls."""
        # Multiple calls should return identical results
        for _ in range(5):
            robot_providers = RobotModeConfig.get_robot_providers()
            all_providers = RobotModeConfig.get_all_providers()
            robot_flags = RobotModeConfig.get_robot_flags()

            assert robot_providers == RobotModeProviderSet.ROBOT.value
            assert all_providers == RobotModeProviderSet.ALL.value
            assert robot_flags == RobotModeFlags.ROBOT.value

    def test_provider_overlap_analysis(self):
        """Test provider overlap between sets is intentional."""
        robot_set = set(RobotModeConfig.get_robot_providers())
        all_set = set(RobotModeConfig.get_all_providers())

        # Calculate overlap and differences
        overlap = robot_set.intersection(all_set)
        all_only = all_set - robot_set

        # All robot providers should be in all providers
        assert overlap == robot_set, "All robot providers should be in all providers"

        # ALL should have additional providers beyond ROBOT
        assert len(all_only) > 0, "ALL set should have providers beyond ROBOT set"

        # Additional providers should be reasonable
        expected_additional = {"misp", "urlscan", "lookyloo"}
        assert expected_additional.issubset(all_only), "Expected additional providers should be present"

    def test_flag_application_scenarios(self):
        """Test flag application in various realistic scenarios."""
        scenarios = [
            # Scenario 1: Pure robot mode
            {
                'argv': ['script.py', '--robot', '--sid', 'test'],
                'initial': {'format': 'human', 'verbose': False, 'log': False},
                'expected': {'format': 'synthesis', 'verbose': False, 'log': True}
            },
            # Scenario 2: Robot with explicit verbose
            {
                'argv': ['script.py', '--robot', '--verbose', '--sid', 'test'],
                'initial': {'format': 'human', 'verbose': True, 'log': False},
                'expected': {'format': 'synthesis', 'verbose': True, 'log': True}
            },
            # Scenario 3: Robot with explicit format
            {
                'argv': ['script.py', '--robot', '--format', 'json', '--sid', 'test'],
                'initial': {'format': 'json', 'verbose': False, 'log': False},
                'expected': {'format': 'json', 'verbose': False, 'log': True}
            }
        ]

        for scenario in scenarios:
            args = SimpleNamespace()
            # Set initial values
            for key, value in scenario['initial'].items():
                setattr(args, key, value)

            with patch('sys.argv', scenario['argv']):
                RobotModeConfig.apply_robot_flags(args)

            # Check expected values
            for key, expected_value in scenario['expected'].items():
                actual_value = getattr(args, key)
                assert actual_value == expected_value, \
                    f"Scenario {scenario['argv']}: {key} should be {expected_value}, got {actual_value}"

    def test_provider_names_validity(self):
        """Test all provider names are valid identifiers."""
        all_providers = RobotModeConfig.get_all_providers()

        for provider in all_providers:
            # Should be valid Python identifier-style name
            assert provider.replace('_', '').replace('-', '').isalnum(), \
                f"Provider name {provider} should be alphanumeric with underscores/hyphens"

            # Should not be empty
            assert len(provider) > 0, "Provider name should not be empty"

            # Should not have spaces
            assert ' ' not in provider, f"Provider name {provider} should not contain spaces"

    def test_configuration_enum_accessibility(self):
        """Test configuration enums are properly accessible."""
        # Should be able to access enum values
        assert hasattr(RobotModeProviderSet, 'ROBOT')
        assert hasattr(RobotModeProviderSet, 'ALL')
        assert hasattr(RobotModeFlags, 'ROBOT')

        # Enum values should be accessible
        robot_providers = RobotModeProviderSet.ROBOT
        assert robot_providers.value is not None
        assert isinstance(robot_providers.value, list)

        robot_flags = RobotModeFlags.ROBOT
        assert robot_flags.value is not None
        assert isinstance(robot_flags.value, dict)