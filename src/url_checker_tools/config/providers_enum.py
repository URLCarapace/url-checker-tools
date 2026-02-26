#!/usr/bin/env python3
"""Enumeration-based provider configuration for better maintainability and type safety."""

from enum import Enum


class ProviderType(Enum):
    """Enumeration of all available provider types."""

    WHALEBONE = "whalebone"
    VIRUSTOTAL = "virustotal"
    WHOIS = "whois"
    GOOGLE_SAFEBROWSING = "google_sb"
    ABUSEIPDB = "abuseipdb"
    URLSCAN = "urlscan"
    LOOKYLOO = "lookyloo"
    YARA = "yara"
    LINK_ANALYZER = "link_analyzer"
    MISP = "misp"


class WhaleboneContentCategory(Enum):
    """Whalebone content categories based on actual API response (from old design)."""

    # Security threat categories (malicious)
    COINMINER = "coinminer"
    TERRORISM = "terrorism"
    CHILD_ABUSE = "child-abuse"
    WEAPONS = "weapons"
    DRUGS = "drugs"
    RACISM = "racism"
    VIOLENCE = "violence"
    FAKENEWS = "fakenews"
    # Policy block categories (blocked by policy, not direct security threats)
    PORN = "porn"
    GAMBLING = "gambling"
    P2P = "p2p"
    DOH = "doh"  # DNS over HTTPS
    TRACKING = "tracking"
    ADVERTISEMENT = "advertisement"
    # Safe categories (whitelisted)
    AUDIO_VIDEO = "audio-video"
    SOCIAL_NETWORKS = "social-networks"
    GAMES = "games"
    CHAT = "chat"


class WhaleboneCategoryClassification(Enum):
    """Classification levels for Whalebone categories."""

    SECURITY_THREAT = "security_threat"
    POLICY_BLOCK = "policy_block"
    SAFE = "safe"


class ProviderEndpoints(Enum):
    """Enumeration of provider API endpoints."""

    WHALEBONE = "https://api.cloud.joindns4.eu/whalebone/2/domain/analysis"
    VIRUSTOTAL = "https://www.virustotal.com/api/v3"
    GOOGLE_SAFEBROWSING = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    URLSCAN = "https://urlscan.io/api/v1"
    ABUSEIPDB = "https://api.abuseipdb.com/api/v2"
    LOOKYLOO = "https://lookyloo.circl.lu"
    MISP = "https://localhost"  # Default localhost MISP


class ProviderDefaults(Enum):
    """Default configuration values for providers."""

    TIMEOUT = 30
    MAX_RETRIES = 3
    RATE_LIMIT = 60


class ProviderRateLimits(Enum):
    """Rate limits for different providers."""

    VIRUSTOTAL_FREE = 4  # per minute
    VIRUSTOTAL_PAID = 1000  # per minute
    GOOGLE_SAFEBROWSING = 60
    URLSCAN = 60
    ABUSEIPDB = 60
    WHALEBONE = 60
    LOOKYLOO = 30  # Conservative rate limit


class GlobalConfig:
    """Global configuration using enumerations."""

    DEFAULT_TIMEOUT = ProviderDefaults.TIMEOUT.value
    DEFAULT_RETRIES = ProviderDefaults.MAX_RETRIES.value
    DEFAULT_RATE_LIMIT = ProviderDefaults.RATE_LIMIT.value
    VERBOSE = False
    LOG_LEVEL = "INFO"

    # Logging configuration
    LOGGING_ENABLED = True
    LOG_DIR = "data/logs"
    STRUCTURED_LOGGING = True
    LOG_API_REQUESTS = False  # Set to True for debugging (may log sensitive data)
