#!/usr/bin/env python3
"""Robot mode configuration and flag management."""

from enum import Enum
from typing import Any, Dict, List


class ProviderSets(Enum):
    """Provider set configurations."""

    # Baseline providers - always run unless explicitly overridden
    BASELINE = [
        "whois",
        "link_analyzer",
        "misp"
    ]

    # Robot mode providers - full threat analysis suite for automation
    ROBOT = [
        "whois",
        "misp",
        "link_analyzer",
        "whalebone",
        "virustotal",
        "google_sb",
        "yara",
        "abuseipdb"
    ]

    # All available providers - comprehensive analysis
    ALL = [
        "whois",
        "link_analyzer",
        "whalebone",
        "misp",
        "virustotal",
        "google_sb",
        "yara",
        "abuseipdb",
        "urlscan",
        "lookyloo",
    ]


class RobotModeFlags(Enum):
    """Robot mode flags."""

    ROBOT = {
        "log": True,
        "score": True,
        "format": "synthesis",
        "verbose": False,
        "misp_report": False,
        "auto_scan_files": False,
    }


class ProviderConfig:
    """Provider configuration with enumerated provider sets and flags."""

    @staticmethod
    def get_baseline_providers() -> List[str]:
        """Get baseline providers (whois and link_analyzer only)."""
        return ProviderSets.BASELINE.value

    @staticmethod
    def get_robot_providers() -> List[str]:
        """Get providers for robot mode."""
        return ProviderSets.ROBOT.value

    @staticmethod
    def get_all_providers() -> List[str]:
        """Get all available providers."""
        return ProviderSets.ALL.value


class RobotModeConfig:
    """Robot mode configuration with enumerated provider sets and flags."""

    @staticmethod
    def get_robot_providers() -> List[str]:
        """Get providers for robot mode."""
        return ProviderSets.ROBOT.value

    @staticmethod
    def get_all_providers() -> List[str]:
        """Get all available providers."""
        return ProviderSets.ALL.value

    @staticmethod
    def get_robot_flags() -> Dict[str, Any]:
        """Get robot mode flags configuration."""
        return RobotModeFlags.ROBOT.value.copy()

    @staticmethod
    def apply_robot_flags(args):
        """Apply robot mode flags to args, preserving existing explicit flags.

        Notes:
        - Argparse always sets defaults (e.g., format="human") even when the user
          didn't pass the flag. To truly preserve explicit user choices, we check
          sys.argv for the presence of the corresponding CLI switches.
        """
        robot_flags = RobotModeConfig.get_robot_flags()

        try:
            import sys as _sys

            argv = _sys.argv
        except Exception:
            argv = []

        def _flag_explicitly_set(name: str) -> bool:
            mapping = {
                "format": "--format",
                "log": "--log",
                "score": "--score",
                "score_detail": "--score-detail",
                "verbose": "--verbose",
                "misp_report": "--misp-report",
                "auto_scan_files": "--auto-scan-files",
            }
            switch = mapping.get(name)
            return bool(switch and switch in argv)

        for flag_name, flag_value in robot_flags.items():
            if flag_name == "format":
                if not _flag_explicitly_set("format"):
                    args.format = flag_value
            elif flag_name == "log":
                if not _flag_explicitly_set("log") and not getattr(args, "log", False):
                    args.log = flag_value
            elif flag_name == "score":
                if (
                    not _flag_explicitly_set("score")
                    and not _flag_explicitly_set("score_detail")
                    and not getattr(args, "score", False)
                    and not getattr(args, "score_detail", False)
                ):
                    args.score = flag_value
            elif flag_name == "score_detail":
                if not _flag_explicitly_set("score_detail") and not getattr(
                    args, "score_detail", False
                ):
                    args.score_detail = flag_value
                    args.score = True  # score_detail implies score
            elif flag_name == "verbose":
                if not _flag_explicitly_set("verbose") and not getattr(
                    args, "verbose", False
                ):
                    args.verbose = flag_value
            elif flag_name == "misp_report":
                if not _flag_explicitly_set("misp_report") and not getattr(
                    args, "misp_report", False
                ):
                    args.misp_report = flag_value
            elif flag_name == "auto_scan_files":
                if not _flag_explicitly_set("auto_scan_files") and not getattr(
                    args, "auto_scan_files", False
                ):
                    args.auto_scan_files = flag_value

        return args
