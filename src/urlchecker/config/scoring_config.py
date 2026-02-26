#!/usr/bin/env python3
"""Scoring configuration for threat assessment system."""

from dataclasses import dataclass
from typing import Dict, Tuple

from urlchecker.core.results import ThreatLevel


@dataclass
class ScoringConfig:
    """Configuration for threat scoring system."""

    # Verdict thresholds (score ranges)
    verdict_thresholds: Dict[str, Tuple[int, int]] = None

    # Base scores for threat levels
    threat_level_scores: Dict[ThreatLevel, int] = None

    # Provider reliability multipliers
    provider_reliability: Dict[str, float] = None

    # Multi-provider boost settings
    multi_provider_threshold: int = 2
    multi_provider_multiplier: float = 1.3

    def __post_init__(self):
        """Initialize default values if not provided."""
        if self.verdict_thresholds is None:
            self.verdict_thresholds = {
                "SAFE": (0, 29),
                "SUSPICIOUS": (30, 59),
                "MALICIOUS": (60, 79),
                "CRITICAL": (80, 100),
            }

        if self.threat_level_scores is None:
            self.threat_level_scores = {
                ThreatLevel.SAFE: 0,
                ThreatLevel.SUSPICIOUS: 30,
                ThreatLevel.MALICIOUS: 70,
                ThreatLevel.CRITICAL: 90,
                ThreatLevel.ERROR: 0,
            }

        if self.provider_reliability is None:
            self.provider_reliability = {
                "whalebone": 1.2,
                "virustotal": 1.15,
                "google_sb": 1.1,
                "urlscan": 1.0,
                "yara": 1.0,
                "whois": 0.3,
                "abuseipdb": 0.8,
                "misp": 1.1,
                "lookyloo": 0.7,
                "link_analyzer": 1.1,
            }


# Default configuration instance
DEFAULT_SCORING_CONFIG = ScoringConfig()


def get_scoring_config() -> ScoringConfig:
    """Get the default scoring configuration."""
    return DEFAULT_SCORING_CONFIG


def create_custom_scoring_config(
    verdict_thresholds: Dict[str, Tuple[int, int]] = None,
    threat_level_scores: Dict[ThreatLevel, int] = None,
    provider_reliability: Dict[str, float] = None,
    multi_provider_threshold: int = 2,
    multi_provider_multiplier: float = 1.3,
) -> ScoringConfig:
    """Create a custom scoring configuration."""
    return ScoringConfig(
        verdict_thresholds=verdict_thresholds,
        threat_level_scores=threat_level_scores,
        provider_reliability=provider_reliability,
        multi_provider_threshold=multi_provider_threshold,
        multi_provider_multiplier=multi_provider_multiplier,
    )
